package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/mcpserver"
	"trstctl.com/trstctl/internal/query"
	"trstctl.com/trstctl/internal/rca"
)

// This file is the SERVED AI / RCA / NL-query / MCP surface (SURFACE-003 / F75/F76/
// F77/F78). Until now internal/aimodel, internal/rca, internal/mcpserver, and
// internal/query were a library island: real, tested code that NO served composition
// imported, so the advertised AI features ran in no binary. Here that island is
// mounted on the running control plane behind the SAME authenticated, RBAC-gated,
// tenant-scoped path every other read route uses:
//
//   - POST /api/v1/ai/query  — a typed semantic/NL query over the tenant's own data
//     surfaces (owners, certificates, graph, CBOM, the event log), answered ONLY from
//     the caller's tenant under PostgreSQL RLS (AN-1), denied before any read if the
//     principal lacks a surface's read permission (F75).
//   - POST /api/v1/ai/rca    — a grounded root-cause / NL question answered ONLY from
//     cited real records gathered through the same scoping seam; every claim carries a
//     citation, and "insufficient evidence" is preferred to a guess (F77).
//   - GET  /api/v1/mcp/tools — list the READ-ONLY MCP tools an external AI agent may
//     call (F78). There are no write/remediation tools.
//   - POST /api/v1/mcp/tools/{tool} — invoke one read-only MCP tool, tenant-scoped,
//     rate-limited, grounded-and-cited, injection-inert (the retrieved data is inert).
//
// The security model the library proved (SURFACE-I02) is preserved by construction:
//   - Tenant floor (AN-1): the tenant is the authenticated principal's, NEVER a request
//     field; the query engine reads under RLS for that tenant only and drops foreign
//     events from the (non-RLS) log in-process. A caller cannot name another tenant.
//   - Read-only: there is no action/remediation path. The MCP surface exposes only the
//     four read tools and HasWriteTool() is false.
//   - Injection-inert: retrieved records (a SAN, a secret name, an evidence summary)
//     are treated as untrusted DATA, never as instructions; there is nothing the model
//     could be induced to DO.
//   - Secret egress (AN-8): when a model IS configured, every prompt crosses
//     aimodel.Adapter.Reason, which redacts with aimodel.DefaultRedactor and then
//     REFUSES the send on any residual high-entropy run (SURFACE-004). The default is
//     NO model (air-gapped/opt-in per the product posture): grounding + citations still
//     work, the synthesized text is the cited evidence itself, and nothing phones home.
//
// The whole surface is OFF unless the server wires WithAISurface (fail closed), and
// each route is registered in the route registry with a read permission so guard()
// enforces RBAC + the per-tenant rate limiter + CSRF before the handler runs.

// AISurfaceBackend is the dependency set the served AI/RCA/MCP surface needs. The
// server builds it (wiring the tenant-scoped query.Engine, the AN-2 event log as an
// auditor, and the optional, opt-in model adapter) and hands it in via WithAISurface,
// so the api package owns the HTTP surface while the composition stays in
// internal/server.
type AISurfaceBackend struct {
	// Query is the semantic query layer (SF.7): the tenant-then-RBAC scoping boundary
	// every AI consumer routes through. Required. Reads run under RLS for the caller's
	// tenant only (AN-1); a query touching a surface the principal can't read is denied
	// before any read executes.
	Query *query.Engine
	// Audit records AI/RCA/MCP calls to the AN-2 event log. A Nop is acceptable for a
	// bare embed; the served path wires the log-backed one.
	Audit auditsink.Auditor
	// Model is the OPTIONAL, opt-in AI model adapter (F76). Nil (the default) means
	// AI reasoning is OFF (air-gapped): grounding + citations still work and the
	// answer is the cited evidence. When set, every prompt crosses the adapter's
	// boundary redactor + residual-entropy refuse-gate before any egress (AN-8).
	Model *aimodel.Adapter
	// ModelStatus is the operator-visible posture of the configured model adapter.
	// It deliberately carries only non-secret facts: mode, provider/runtime label,
	// model name, endpoint host, and whether egress is none/local/cloud.
	ModelStatus AIModelStatus
	// MCPIdentity is the workload identity this MCP server presents (dogfooding the
	// F61 broker). Informational; empty is fine.
	MCPIdentity string
	// RateMax / RateWindow bound the per-(caller,tool) MCP call rate
	// (enumeration-abuse protection). Zero selects a conservative default.
	RateMax    int
	RateWindow time.Duration
}

// AIModelStatus is the safe, non-secret model posture the server passes to the API.
// EndpointHost is a host[:port] only; the full URL can carry paths or query values an
// operator may not want echoed in a browser.
type AIModelStatus struct {
	Mode         string
	Runtime      string
	Provider     string
	ModelName    string
	EndpointHost string
	Egress       string
	// PIIEgress is the operator-visible personal-data egress posture (PRIVACY-005):
	// "redact" (default-private: personal/identifying data is stripped before any
	// prompt egress), "block" (refuse a prompt carrying personal data), or "allow"
	// (operator consented to personal-data egress). Non-secret.
	PIIEgress string
}

// aiSurface is the assembled served AI/RCA/MCP surface. It is read-only and
// tenant-scoped by construction (the tenant always comes from the authenticated
// principal, never a request field). The query engine + model adapter are shared
// (concurrency-safe); the rca pipeline/synthesizer and MCP server are built per
// request bound to the caller's principal so scoping is inherited automatically.
type aiSurface struct {
	be   AISurfaceBackend
	rate *mcpserver.RateLimiter
}

// WithAISurface wires the served AI/RCA/NL-query/MCP surface (SURFACE-003). The
// routes are added to the route registry by routes(), so they are RBAC-gated,
// rate-limited, CSRF-defended, and appear in the OpenAPI document. When unset the
// surface is OFF and the routes are not mounted (fail closed).
func WithAISurface(be AISurfaceBackend) Option {
	return func(c *config) { c.ai = newAISurface(be) }
}

// newAISurface constructs the surface, defaulting the rate limiter.
func newAISurface(be AISurfaceBackend) *aiSurface {
	if be.Audit == nil {
		be.Audit = auditsink.Nop{}
	}
	max, window := be.RateMax, be.RateWindow
	if max <= 0 {
		max = 60
	}
	if window <= 0 {
		window = time.Minute
	}
	be.RateMax = max
	be.RateWindow = window
	return &aiSurface{be: be, rate: mcpserver.NewRateLimiter(max, window)}
}

// AISurfaceServed reports whether the running binary mounts the served AI/RCA/MCP
// surface (SURFACE-003) — the wiring assertion the server-level check and the
// acceptance test consult.
func (a *API) AISurfaceServed() bool { return a.ai != nil }

// engineQuery adapts the tenant-then-RBAC-scoped query.Engine to rca.Query: it binds
// the authenticated principal and translates a (tenantID, kind, subject) request into
// a typed query.Spec, so the rca pipeline gathers evidence THROUGH the SF.7 scoping
// seam (the missing adapter the audit called out). The principal is authoritative for
// the tenant AND the RBAC scope: a surface the principal cannot read is denied by the
// engine before any read, and the engine never names a tenant other than the
// principal's. A tenantID that does not match the bound principal is refused outright
// (defense in depth — the handler already binds them equal).
type engineQuery struct {
	engine    *query.Engine
	principal authz.Principal
}

// kindSurface maps an rca query "kind" (the words rca.plan emits) to the typed query
// surface that answers it. Unknown kinds yield no surface (no records), never a wider
// read.
var kindSurface = map[string]query.Surface{
	"graph":      query.SurfaceGraph, // blast radius / reachability
	"compliance": query.SurfaceCBOM,  // crypto bill of materials → compliance gaps
	"audit":      query.SurfaceLog,   // the event log: what happened
}

// Run implements rca.Query. It selects the typed surface that answers the requested
// kind and runs it scoped to the bound principal (AN-1 + RBAC) — the security floor is
// PostgreSQL RLS (relational surfaces) + the in-process tenant drop (the log), so no
// row from another tenant is reachable regardless of the subject. The subject is a
// FREE-FORM identifier (e.g. a workload name or a cert serial), NOT one of the query
// layer's typed enums (a graph node KIND, a CBOM ALGORITHM), so it is applied as a SOFT
// in-process relevance filter over the tenant-scoped rows, never as a hard typed
// predicate that would wrongly drop all evidence when the subject is not an enum value.
// A subject that matches nothing falls back to the whole tenant-scoped surface, so the
// pipeline still grounds the answer in real records rather than returning empty.
func (q engineQuery) Run(ctx context.Context, tenantID, kind, subject string) ([]rca.Record, error) {
	if tenantID != q.principal.TenantID {
		// The handler binds these equal; a mismatch can only be a programming error or
		// an attempt to widen scope. Fail closed rather than read another tenant.
		return nil, errors.New("api: ai query tenant does not match the authenticated principal")
	}
	surf, ok := kindSurface[kind]
	if !ok {
		return nil, nil
	}
	res, err := q.engine.Query(ctx, q.principal, query.Spec{Select: []query.Surface{surf}})
	if err != nil {
		// Map the engine's coarse forbidden/backpressure errors to nil-evidence vs a
		// surfaced error: a forbidden surface means the caller may simply not see that
		// evidence kind, which the pipeline treats as "no records" rather than a hard
		// failure of the whole answer.
		if errors.Is(err, query.ErrForbidden) {
			return nil, nil
		}
		return nil, err
	}

	// Build records from the tenant-scoped rows. Apply the subject as a SOFT relevance
	// filter: keep rows whose identifying columns mention the subject, but if that would
	// drop everything (the subject is not a literal in this surface), fall back to all
	// tenant-scoped rows so the answer is still grounded.
	all := make([]rca.Record, 0, len(res.Rows))
	matched := make([]rca.Record, 0, len(res.Rows))
	for _, row := range res.Rows {
		rec := rca.Record{Source: string(row.Surface), ID: recordID(row), Summary: rowSummary(row)}
		all = append(all, rec)
		if subject != "" && rowMentions(row, subject) {
			matched = append(matched, rec)
		}
	}
	if subject != "" && len(matched) > 0 {
		return matched, nil
	}
	return all, nil
}

// rowMentions reports whether any column value of a scoped row mentions the subject
// (case-insensitive substring) — the soft relevance match used to focus evidence on a
// subject without ever dropping all of it. It reads only already-tenant-scoped,
// non-secret columns.
func rowMentions(row query.Row, subject string) bool {
	s := strings.ToLower(subject)
	for _, v := range row.Columns {
		if strings.Contains(strings.ToLower(v), s) {
			return true
		}
	}
	return false
}

// recordID derives a stable citation id from a scoped row (prefers an "id" column,
// else the first stable identifying column for the surface).
func recordID(row query.Row) string {
	for _, k := range []string{"id", "serial", "name", "location"} {
		if v, ok := row.Columns[k]; ok && v != "" {
			return v
		}
	}
	return string(row.Surface)
}

// rowSummary renders a scoped row into a short human summary for evidence. It carries
// only already-scoped, non-secret inventory columns; the rca pipeline additionally
// runs aimodel.DefaultRedactor over every summary before it becomes evidence (AN-8),
// so even an unexpected column value cannot smuggle key material into a prompt.
func rowSummary(row query.Row) string {
	switch row.Surface {
	case query.SurfaceLog:
		return "event type=" + row.Columns["type"]
	case query.SurfaceGraph:
		return "graph node kind=" + row.Columns["kind"] + " name=" + row.Columns["name"]
	case query.SurfaceCBOM:
		return "crypto asset algorithm=" + row.Columns["algorithm"] + " location=" + row.Columns["location"] + " strength=" + row.Columns["strength"]
	case query.SurfaceCertificates:
		return "certificate serial=" + row.Columns["serial"] + " subject=" + row.Columns["subject"]
	case query.SurfaceOwners:
		return "owner name=" + row.Columns["name"]
	default:
		return string(row.Surface)
	}
}

// principalFor returns the authenticated principal placed in the request context by
// guard, and whether it is present. Every AI route is RBAC-gated, so guard has already
// run and the principal (with its tenant + grants) is authoritative.
func (a *API) principalFor(r *http.Request) (authz.Principal, bool) {
	p, ok := r.Context().Value(principalCtxKey).(authz.Principal)
	return p, ok && p.TenantID != ""
}
