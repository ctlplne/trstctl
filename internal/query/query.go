// SPDX-License-Identifier: BUSL-1.1

// Package query is trstctl's semantic query layer: one internal, read-only API
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

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
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

// CertificateExpiryWindow selects active certificates whose not_after is after
// After and before Before. The reader sends both bounds as typed values through
// the tenant-scoped store; callers cannot supply SQL or a tenant selector.
type CertificateExpiryWindow struct {
	After  time.Time
	Before time.Time
}

// CertificateFilter is a typed certificate question, usually the question
// planner's output. The store binds every field as a parameter; none is ever
// formatted into statement text. Zero fields do not filter.
type CertificateFilter struct {
	// Status is "active", "revoked" or "superseded"; empty means any status.
	Status string
	// ExpiresAfter and ExpiresBefore bound the expiry, exclusively; nil is open.
	ExpiresAfter, ExpiresBefore *time.Time
	// IssuerContains and NameContains are case-insensitive literal substrings
	// of the issuer, and of the subject or any SAN.
	IssuerContains, NameContains string
	// KeyAlgorithm is a key algorithm family: it matches the recorded algorithm
	// case-insensitively, exactly or as the part before a dash.
	KeyAlgorithm string
	// OwnerName selects certificates whose owner has this name, case aside; it
	// needs the owners surface. Unowned selects certificates with no owner.
	OwnerName string
	Unowned   bool
	// Serial and Fingerprint select one certificate exactly, case aside.
	Serial, Fingerprint string
}

// CryptoAssetFilter is a typed question over the CBOM.
type CryptoAssetFilter struct {
	// Algorithm is a key algorithm family, matched like CertificateFilter's.
	Algorithm string
	// KeyBitsBelow selects assets with a recorded key size below it.
	KeyBitsBelow int
	// QuantumVulnerable and OutOfPolicy select assets the CBOM classified so.
	QuantumVulnerable, OutOfPolicy bool
}

// maxFilterValue bounds a filter value taken from a question.
const maxFilterValue = 200

// Spec is a typed, parameterized query plan. It has NO tenant or scope field:
// the tenant and RBAC scope come from the authenticated Principal, so a caller
// cannot widen its own scope. Field/operator names are allow-listed enums.
type Spec struct {
	Select                  []Surface
	Where                   []Predicate
	CertificateExpiryWindow *CertificateExpiryWindow
	// Focus, when set, names the selected surfaces whose rows answer the query.
	// The others are still authorized — a caller cannot smuggle an unreadable
	// selection past the denial — but are not read. A certificate expiry window
	// or certificate filter focuses on certificates, a crypto-asset filter on the
	// CBOM.
	Focus []Surface
	// Certificates and CryptoAssets filter one surface each; a spec may carry at
	// most one of them. Count asks for the exact number of matches as well.
	Certificates *CertificateFilter
	CryptoAssets *CryptoAssetFilter
	Count        bool
	Limit        int // hard-capped by Config.MaxRows
	MaxDepth     int // graph traversal bound, hard-capped by Config.MaxDepth
}

// Row is one result row: the surface it came from and its typed columns.
type Row struct {
	Surface Surface
	Columns map[string]string
}

// Result carries the scoped rows plus the tenant-local log offset they are
// consistent with (AN-2): callers can tell which point in their own event-sourced
// model they reflect without seeing the global stream head.
type Result struct {
	Rows      []Row
	Offset    uint64
	Truncated bool // the row or scan budget prevents a complete-result claim
	// Count is the exact number of matches when the Spec asked for it (Counted).
	Count   int
	Counted bool
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
	if window := spec.CertificateExpiryWindow; window != nil {
		if !selected[SurfaceCertificates] || window.After.IsZero() || window.Before.IsZero() || !window.After.Before(window.Before) {
			return fmt.Errorf("%w: invalid certificate expiry window", ErrMalformed)
		}
	}
	if err := validateFilters(spec, selected); err != nil {
		return err
	}
	for _, s := range spec.Focus {
		if !selected[s] {
			return fmt.Errorf("%w: focus on surface %q that is not selected", ErrMalformed, s)
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
	var truncated, counted bool
	var count int

	add := func(r Row) bool {
		if len(rows) >= limit {
			truncated = true
			return false
		}
		rows = append(rows, r)
		return true
	}

	for _, surf := range spec.Select {
		if err := ctx.Err(); err != nil {
			return nil, ErrDeadline
		}
		// A focused query answers from its focus surfaces only. Every requested
		// surface stayed in authorize() above, so a caller cannot smuggle an
		// unauthorized selection through the narrowing step.
		if !spec.reads(surf) {
			continue
		}
		var err error
		switch surf {
		case SurfaceOwners:
			err = e.readOwners(ctx, p.TenantID, eq, add)
		case SurfaceCertificates:
			var scanTruncated bool
			if spec.Certificates != nil {
				scanTruncated, err = e.readFilteredCertificates(ctx, p.TenantID, *spec.Certificates, limit, add)
				if err == nil && spec.Count {
					count, err = e.store.CountCertificates(ctx, p.TenantID, spec.Certificates.store())
					counted = err == nil
				}
			} else {
				scanTruncated, err = e.readCertificates(ctx, p.TenantID, eq, spec.CertificateExpiryWindow, limit, add)
			}
			truncated = truncated || scanTruncated
		case SurfaceGraph:
			err = e.readGraph(ctx, p.TenantID, eq, add)
		case SurfaceCBOM:
			var matches int
			matches, err = e.readCBOM(ctx, p.TenantID, eq, spec.CryptoAssets, add)
			if err == nil && spec.Count {
				count, counted = matches, true
			}
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

	return &Result{Rows: rows, Offset: offset, Truncated: truncated, Count: count, Counted: counted}, nil
}

// reads reports whether surf's rows belong in the answer.
func (spec Spec) reads(surf Surface) bool {
	focus := spec.Focus
	switch {
	case len(focus) > 0:
	case spec.CertificateExpiryWindow != nil || spec.Certificates != nil:
		focus = []Surface{SurfaceCertificates}
	case spec.CryptoAssets != nil:
		focus = []Surface{SurfaceCBOM}
	default:
		return true
	}
	for _, s := range focus {
		if s == surf {
			return true
		}
	}
	return false
}

// validateFilters checks the typed surface filters against the selection.
func validateFilters(spec Spec, selected map[Surface]bool) error {
	if spec.Certificates != nil && spec.CryptoAssets != nil {
		return fmt.Errorf("%w: a spec filters one surface", ErrMalformed)
	}
	if spec.Count && spec.Certificates == nil && spec.CryptoAssets == nil {
		return fmt.Errorf("%w: count needs a filtered surface", ErrMalformed)
	}
	if f := spec.Certificates; f != nil {
		if !selected[SurfaceCertificates] || spec.CertificateExpiryWindow != nil {
			return fmt.Errorf("%w: a certificate filter needs the certificates surface and no expiry window", ErrMalformed)
		}
		switch f.Status {
		case "", "active", "revoked", "superseded":
		default:
			return fmt.Errorf("%w: unknown certificate status", ErrMalformed)
		}
		if f.ExpiresAfter != nil && f.ExpiresBefore != nil && !f.ExpiresAfter.Before(*f.ExpiresBefore) {
			return fmt.Errorf("%w: invalid certificate expiry bounds", ErrMalformed)
		}
		if f.OwnerName != "" && (f.Unowned || !selected[SurfaceOwners]) {
			return fmt.Errorf("%w: an owner filter needs the owners surface", ErrMalformed)
		}
		for _, v := range []string{f.IssuerContains, f.NameContains, f.KeyAlgorithm, f.OwnerName, f.Serial, f.Fingerprint} {
			if len(v) > maxFilterValue {
				return fmt.Errorf("%w: filter value too long", ErrMalformed)
			}
		}
	}
	if f := spec.CryptoAssets; f != nil {
		if !selected[SurfaceCBOM] || f.KeyBitsBelow < 0 || len(f.Algorithm) > maxFilterValue {
			return fmt.Errorf("%w: invalid crypto asset filter", ErrMalformed)
		}
	}
	return nil
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
