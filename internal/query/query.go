// Package query is trustctl's semantic query layer: one internal, read-only API
// that joins across the platform's data surfaces (the event log, the credential
// graph, the cert inventory, and the CBOM) with tenant-then-RBAC scoping enforced
// BY CONSTRUCTION (SF.7, per the SF.6 design in docs/design/semantic-query-layer.md).
//
// The security boundary every later consumer (the AI layer, the MCP server, the
// developer portal, compliance reporting) routes through, so none of them reinvent
// cross-store joins or re-implement scoping, and none are trusted to self-censor.
//
// Enforcement, in three composing layers:
//
//   - Tenant floor (AN-1): every read runs against the caller's tenant only. The
//     tenant comes from the authenticated Principal — there is NO API to query
//     another tenant — and the underlying store reads run under PostgreSQL RLS, so
//     a cross-tenant row is unreachable in the database itself, independent of this
//     layer's own correctness.
//   - RBAC (S3.5): the caller must hold the read permission for every requested
//     surface; a query touching a surface the principal can't read is DENIED before
//     any read executes (not post-filtered).
//   - Typed spec: callers submit a Spec of allow-listed surfaces/fields/operators
//     with values bound as parameters — never raw SQL/Cypher — so neither a field
//     name nor an operator can be attacker-controlled.
//
// Cost/timeout guards (AN-7): queries run on a bounded pool, with row and graph-depth
// caps and a wall-clock deadline; an over-budget or runaway query fails closed.
package query

import (
	"context"
	"errors"
	"fmt"
	"time"

	"trustctl.io/trustctl/internal/authz"
	"trustctl.io/trustctl/internal/bulkhead"
	"trustctl.io/trustctl/internal/events"
	"trustctl.io/trustctl/internal/store"
)

// Surface is one allow-listed data surface the engine can read and join.
type Surface string

const (
	SurfaceOwners       Surface = "owners"       // inventory: owners
	SurfaceCertificates Surface = "certificates" // inventory: certificates
	SurfaceGraph        Surface = "graph"        // credential graph (F21)
	SurfaceCBOM         Surface = "cbom"         // cryptographic bill of materials (F52)
	SurfaceLog          Surface = "log"          // the event/audit log (AN-2 source of truth)
)

// requiredPermission maps a surface to the RBAC permission a principal must hold to
// read it. A surface absent from this map is unknown and fails closed.
var requiredPermission = map[Surface]authz.Permission{
	SurfaceOwners:       authz.OwnersRead,
	SurfaceCertificates: authz.CertsRead,
	SurfaceGraph:        authz.GraphRead,
	SurfaceCBOM:         authz.RiskRead,
	SurfaceLog:          authz.AuditRead,
}

// Field is an allow-listed, filterable field, named "<surface>.<column>". Only
// fields in allowedFields may appear in a predicate; anything else fails closed.
type Field string

const (
	FieldOwnerID       Field = "certificates.owner_id"
	FieldCertSerial    Field = "certificates.serial"
	FieldOwnerName     Field = "owners.name"
	FieldLogType       Field = "log.type"
	FieldCBOMAlgorithm Field = "cbom.algorithm"
	FieldGraphNodeKind Field = "graph.kind"
)

var fieldSurface = map[Field]Surface{
	FieldOwnerID:       SurfaceCertificates,
	FieldCertSerial:    SurfaceCertificates,
	FieldOwnerName:     SurfaceOwners,
	FieldLogType:       SurfaceLog,
	FieldCBOMAlgorithm: SurfaceCBOM,
	FieldGraphNodeKind: SurfaceGraph,
}

// Op is an allow-listed comparison operator. Equality only, for now — enough to
// scope/filter without opening an injection surface.
type Op string

const OpEq Op = "eq"

// Predicate is one typed filter: a field, an operator, and a bound value. The
// value is only ever compared in-process against the typed field — never spliced
// into a statement.
type Predicate struct {
	Field Field
	Op    Op
	Value string
}

// Spec is a typed, parameterized query plan. It has NO tenant or scope field:
// the tenant and RBAC scope come from the authenticated Principal, so a caller
// cannot widen its own scope. Field/operator names are allow-listed enums.
type Spec struct {
	Select   []Surface
	Where    []Predicate
	Limit    int // hard-capped by Config.MaxRows
	MaxDepth int // graph traversal bound, hard-capped by Config.MaxDepth
}

// Row is one result row: the surface it came from and its typed columns.
type Row struct {
	Surface Surface
	Columns map[string]string
}

// Result carries the scoped rows plus the log offset they are consistent with
// (AN-2): callers can tell which point in the event-sourced model they reflect.
type Result struct {
	Rows   []Row
	Offset uint64
}

// Config sets the cost/timeout guards.
type Config struct {
	MaxRows  int           // hard cap on returned rows per query
	MaxDepth int           // hard cap on graph traversal depth
	Timeout  time.Duration // wall-clock deadline per query
}

// DefaultConfig is a conservative guard profile.
func DefaultConfig() Config { return Config{MaxRows: 1000, MaxDepth: 8, Timeout: 5 * time.Second} }

// Errors are intentionally coarse so a caller cannot distinguish "out of scope"
// from "not found" (no result-shape inference, V6 in the design).
var (
	ErrForbidden    = errors.New("query: forbidden")               // RBAC denied a requested surface
	ErrMalformed    = errors.New("query: malformed spec")          // unknown surface/field/operator, or inconsistent plan
	ErrCostExceeded = errors.New("query: cost guard exceeded")     // over the row/depth budget
	ErrRejected     = errors.New("query: rejected (backpressure)") // the bounded pool was full
	ErrDeadline     = errors.New("query: deadline exceeded")       // wall-clock guard tripped
)

// Engine runs scoped queries over the data surfaces. It is safe for concurrent
// use. The store provides the AN-1 RLS-backed reads and the graph; the log is the
// event surface; the pool bounds concurrency (AN-7).
type Engine struct {
	store *store.Store
	log   *events.Log
	pool  *bulkhead.Pool
	cfg   Config
}

// New builds an Engine. A nil pool means run inline (no bulkhead) — tests may pass
// nil; production wires a bounded "query" pool.
func New(st *store.Store, log *events.Log, pool *bulkhead.Pool, cfg Config) *Engine {
	if cfg.MaxRows <= 0 {
		cfg.MaxRows = DefaultConfig().MaxRows
	}
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = DefaultConfig().MaxDepth
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultConfig().Timeout
	}
	return &Engine{store: st, log: log, pool: pool, cfg: cfg}
}

// Query runs spec for principal p and returns the scoped, joined result. The
// tenant is p.TenantID throughout; there is no way for spec to name another tenant.
func (e *Engine) Query(ctx context.Context, p authz.Principal, spec Spec) (*Result, error) {
	if err := e.validate(spec); err != nil {
		return nil, err
	}
	if err := e.authorize(p, spec); err != nil {
		return nil, err
	}

	// Wall-clock guard: bound the whole query and cancel underlying reads if it trips.
	qctx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()

	type outcome struct {
		res *Result
		err error
	}
	done := make(chan outcome, 1)
	run := func() { res, err := e.run(qctx, p, spec); done <- outcome{res, err} }

	// AN-7: run on the bounded pool when wired, so a heavy query can't starve other
	// subsystems and a saturated pool fails fast.
	if e.pool != nil {
		if err := e.pool.Submit(run); err != nil {
			return nil, ErrRejected
		}
	} else {
		go run()
	}

	select {
	case <-qctx.Done():
		return nil, ErrDeadline
	case o := <-done:
		return o.res, o.err
	}
}

// validate enforces the typed-spec allow-lists (no raw input) and the static cost
// caps. Anything unknown or over-budget fails closed before execution.
func (e *Engine) validate(spec Spec) error {
	if len(spec.Select) == 0 {
		return fmt.Errorf("%w: no surfaces selected", ErrMalformed)
	}
	selected := map[Surface]bool{}
	for _, s := range spec.Select {
		if _, ok := requiredPermission[s]; !ok {
			return fmt.Errorf("%w: unknown surface %q", ErrMalformed, s)
		}
		selected[s] = true
	}
	for _, pr := range spec.Where {
		surf, ok := fieldSurface[pr.Field]
		if !ok {
			return fmt.Errorf("%w: unknown field %q", ErrMalformed, pr.Field)
		}
		if pr.Op != OpEq {
			return fmt.Errorf("%w: unknown operator %q", ErrMalformed, pr.Op)
		}
		if !selected[surf] {
			return fmt.Errorf("%w: predicate on field %q whose surface %q is not selected", ErrMalformed, pr.Field, surf)
		}
	}
	if spec.Limit < 0 || spec.Limit > e.cfg.MaxRows {
		return fmt.Errorf("%w: limit %d exceeds max %d", ErrCostExceeded, spec.Limit, e.cfg.MaxRows)
	}
	if spec.MaxDepth < 0 || spec.MaxDepth > e.cfg.MaxDepth {
		return fmt.Errorf("%w: depth %d exceeds max %d", ErrCostExceeded, spec.MaxDepth, e.cfg.MaxDepth)
	}
	return nil
}

// authorize denies the whole query if the principal lacks read permission for any
// requested surface — denial before execution, scoped to the principal's own
// tenant (AN-1). Scope is derived from the principal, never from the spec.
func (e *Engine) authorize(p authz.Principal, spec Spec) error {
	tenantScope := authz.Scope{TenantID: p.TenantID}
	for _, s := range spec.Select {
		if !p.Can(requiredPermission[s], tenantScope) {
			return ErrForbidden
		}
	}
	return nil
}

// run executes the authorized, validated plan within the principal's tenant. Every
// read is tenant-scoped by p.TenantID; the store enforces RLS underneath.
func (e *Engine) run(ctx context.Context, p authz.Principal, spec Spec) (*Result, error) {
	limit := spec.Limit
	if limit == 0 || limit > e.cfg.MaxRows {
		limit = e.cfg.MaxRows
	}
	eq := predicateIndex(spec.Where)
	var rows []Row
	var offset uint64

	add := func(r Row) bool {
		if len(rows) >= limit {
			return false
		}
		rows = append(rows, r)
		return true
	}

	for _, surf := range spec.Select {
		if err := ctx.Err(); err != nil {
			return nil, ErrDeadline
		}
		var err error
		switch surf {
		case SurfaceOwners:
			err = e.readOwners(ctx, p.TenantID, eq, add)
		case SurfaceCertificates:
			err = e.readCertificates(ctx, p.TenantID, eq, add)
		case SurfaceGraph:
			err = e.readGraph(ctx, p.TenantID, eq, add)
		case SurfaceCBOM:
			err = e.readCBOM(ctx, p.TenantID, eq, add)
		case SurfaceLog:
			err = e.readLog(ctx, p.TenantID, eq, limit, &offset, add)
		}
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				return nil, ErrDeadline
			}
			return nil, err
		}
	}

	return &Result{Rows: rows, Offset: offset}, nil
}

// predicateIndex collapses equality predicates to a field→value lookup. With OpEq
// only, a field appearing twice keeps the last value (a degenerate but harmless
// over-constraint).
func predicateIndex(preds []Predicate) map[Field]string {
	m := map[Field]string{}
	for _, p := range preds {
		m[p.Field] = p.Value
	}
	return m
}
