package api

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/mcpserver"
	"trstctl.com/trstctl/internal/query"
	"trstctl.com/trstctl/internal/rca"
)

// This file holds the HTTP handlers for the served AI/RCA/NL-query/MCP surface
// (SURFACE-003). Each handler resolves the AUTHENTICATED principal (guard already ran
// and bound it in the context), builds the rca pipeline/synthesizer or MCP server
// scoped to that principal, and answers ONLY from the caller's tenant. Every model
// egress (when a model is configured) goes through aimodel.Adapter.Reason inside the
// synthesizer, which redacts + refuses on residual entropy (AN-8). All routes are
// read-only; the MCP surface exposes no write tool.

// --- request/response shapes ---

// aiQueryRequest is a typed semantic/NL query (F75). Surfaces and an optional subject
// are allow-listed and bound as typed predicates by the engine; raw SQL/Cypher is
// never accepted (the engine's injection-inert contract).
type aiQueryRequest struct {
	// Surfaces names the data surfaces to read and join (owners, certificates, graph,
	// cbom, log). Each must be one the principal can read or the whole query is denied.
	Surfaces []string `json:"surfaces"`
	// Subject optionally filters to a node kind / algorithm / owner name etc. (bound
	// as a typed predicate, never spliced).
	Subject string `json:"subject,omitempty"`
	// Question is the natural-language question, used to phrase the grounded answer and
	// (when a model is configured) the prompt. It is treated as untrusted text.
	Question string `json:"question,omitempty"`
	// Limit caps returned rows; hard-capped by the engine's MaxRows.
	Limit int `json:"limit,omitempty"`
}

// aiAnswer is a grounded, cited answer (F75/F77). Text is grounded in Citations, which
// reference REAL records; Sufficient is false when there was no evidence (no guess).
type aiAnswer struct {
	Text       string   `json:"text"`
	Citations  []string `json:"citations"`
	Sufficient bool     `json:"sufficient"`
	Grounded   bool     `json:"grounded"`
}

// rcaRequest is a grounded root-cause / NL question over the tenant's data (F77).
type rcaRequest struct {
	Subject  string `json:"subject"`
	Question string `json:"question"`
}

// mcpToolsResponse lists the read-only MCP tools (F78).
type mcpToolsResponse struct {
	Identity string   `json:"identity,omitempty"`
	ReadOnly bool     `json:"read_only"`
	Tools    []string `json:"tools"`
}

// mcpCallRequest invokes one read-only MCP tool (F78).
type mcpCallRequest struct {
	Subject string `json:"subject"`
}

// mcpCallResponse is the grounded, cited tool result (F78).
type mcpCallResponse struct {
	Tool      string   `json:"tool"`
	Citations []string `json:"citations"`
	Text      string   `json:"text"`
}

// --- surface name validation ---

// surfaceByName maps the API's surface filter values to the typed query.Surface. A
// name absent from this map is unknown and rejected (fail closed) before any read.
var surfaceByName = map[string]query.Surface{
	"owners":       query.SurfaceOwners,
	"certificates": query.SurfaceCertificates,
	"graph":        query.SurfaceGraph,
	"cbom":         query.SurfaceCBOM,
	"log":          query.SurfaceLog,
}

// subjectFieldForSurface returns the typed field a subject filters on for the surface,
// or ("", false) when that surface has no subject-typed field (then it is read whole,
// tenant-scoped).
func subjectFieldForSurface(s query.Surface) (query.Field, bool) {
	switch s {
	case query.SurfaceGraph:
		return query.FieldGraphNodeKind, true
	case query.SurfaceCBOM:
		return query.FieldCBOMAlgorithm, true
	case query.SurfaceCertificates:
		return query.FieldCertSerial, true
	case query.SurfaceOwners:
		return query.FieldOwnerName, true
	default:
		return "", false
	}
}

// aiQuery answers a typed semantic/NL query over the tenant's own data surfaces (F75).
// It is read-only; despite being POST (the typed spec travels in the body) it mutates
// no state. The tenant + RBAC scope come from the authenticated principal: a surface
// the principal cannot read denies the whole query (ErrForbidden -> 403), and no row
// from another tenant is reachable (RLS + in-process log tenant drop).
func (a *API) aiQuery(w http.ResponseWriter, r *http.Request) {
	if a.ai == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "AI surface is not enabled"))
		return
	}
	principal, ok := a.principalFor(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var req aiQueryRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if len(req.Surfaces) == 0 {
		a.writeError(w, errStatus(http.StatusBadRequest, "at least one surface is required"))
		return
	}
	spec := query.Spec{Limit: req.Limit}
	for _, name := range req.Surfaces {
		surf, ok := surfaceByName[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			a.writeError(w, errStatus(http.StatusBadRequest, "unknown surface: "+name))
			return
		}
		spec.Select = append(spec.Select, surf)
		if req.Subject != "" {
			if field, has := subjectFieldForSurface(surf); has {
				spec.Where = append(spec.Where, query.Predicate{Field: field, Op: query.OpEq, Value: req.Subject})
			}
		}
	}

	res, err := a.ai.be.Query.Query(r.Context(), principal, spec)
	if err != nil {
		a.writeAIQueryError(w, err)
		return
	}

	// Build a grounded answer from the scoped rows (the same grounding the RCA path
	// uses): cite each row, and when a model is configured, synthesize over the cited
	// evidence with the redact+refuse boundary. Without a model the answer IS the cited
	// evidence (air-gapped default).
	ev := rca.Evidence{Question: req.Question, Subject: req.Subject}
	for _, row := range res.Rows {
		ev.Items = append(ev.Items, rca.EvidenceItem{
			Citation: string(row.Surface) + "#" + recordID(row),
			Summary:  rowSummary(row), // pre-scoped, non-secret columns; redacted again below
		})
	}
	ans := a.synthesize(r, ev)

	_ = auditsink.Emit(r.Context(), a.ai.be.Audit, nil, "ai.query.answered", principal.TenantID,
		[]byte(fmt.Sprintf(`{"subject":%q,"rows":%d,"citations":%d,"grounded":%t}`, req.Subject, len(res.Rows), len(ans.Citations), ans.Grounded)))

	a.writeJSON(w, http.StatusOK, ans)
}

// aiRCA answers a grounded root-cause / NL question over the tenant's data (F77). The
// pipeline plans queries from the question, gathers cited evidence through the SF.7
// scoping seam (tenant + RBAC by construction), and the synthesizer renders a grounded,
// cited answer (preferring "insufficient evidence" to a guess). Read-only.
func (a *API) aiRCA(w http.ResponseWriter, r *http.Request) {
	if a.ai == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "AI surface is not enabled"))
		return
	}
	principal, ok := a.principalFor(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var req rcaRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if strings.TrimSpace(req.Question) == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "question is required"))
		return
	}

	pipeline := rca.NewPipeline(engineQuery{engine: a.ai.be.Query, principal: principal}, a.ai.be.Audit)
	synth := rca.NewSynthesizer(a.ai.be.Model)

	ev, err := pipeline.Gather(r.Context(), principal.TenantID, req.Subject, req.Question)
	if err != nil {
		a.writeError(w, err)
		return
	}
	ans, err := synth.Answer(r.Context(), ev)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, aiAnswer{
		Text:       ans.Text,
		Citations:  ans.Citations,
		Sufficient: ans.Sufficient,
		Grounded:   len(ans.Citations) > 0,
	})
}

// mcpTools lists the read-only MCP tools an external AI agent may call (F78). The list
// is built from an MCP server bound to the caller's tenant; HasWriteTool() is false by
// construction, so the response always reports read_only=true.
func (a *API) mcpTools(w http.ResponseWriter, r *http.Request) {
	if a.ai == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "AI surface is not enabled"))
		return
	}
	principal, ok := a.principalFor(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	srv := a.mcpServerFor(principal)
	a.writeJSON(w, http.StatusOK, mcpToolsResponse{
		Identity: srv.Identity(),
		ReadOnly: !srv.HasWriteTool(),
		Tools:    srv.Tools(),
	})
}

// mcpCall invokes one read-only MCP tool, scoped to the caller's tenant via SF.7,
// rate-limited and audited (F78). The retrieved data is grounded, cited, and inert (a
// hostile string in a record causes no action). An unknown/non-read-only tool is a
// 404; a cross-tenant request can never occur because the tenant is the principal's.
func (a *API) mcpCall(w http.ResponseWriter, r *http.Request) {
	if a.ai == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "AI surface is not enabled"))
		return
	}
	principal, ok := a.principalFor(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	tool := r.PathValue("tool")
	var req mcpCallRequest
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &req); err != nil {
			a.writeError(w, errWithStatus(http.StatusBadRequest, err))
			return
		}
	}

	srv := a.mcpServerFor(principal)
	// The caller key for rate limiting is the authenticated subject, so one principal's
	// enumeration cannot exhaust another's budget.
	res, err := srv.Call(r.Context(), principal.Subject, principal.TenantID, tool, req.Subject)
	if err != nil {
		a.writeMCPCallError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, mcpCallResponse{Tool: res.Tool, Citations: res.Citations, Text: res.Text})
}

// mcpServerFor builds an MCP server bound to the caller's principal, over the
// tenant-scoped query engine (via the rca pipeline) and the shared rate limiter. It is
// constructed per request because the principal is per request; all the heavy state
// (the engine, the limiter) is shared and concurrency-safe. The engineQuery adapter
// carries the REAL authenticated principal, so a tool's evidence gather is denied per
// surface by RBAC (a caller without audit:read simply gets no audit evidence) and is
// confined to the principal's tenant under RLS (AN-1) — the MCP surface cannot widen
// the caller's own scope.
func (a *API) mcpServerFor(principal authz.Principal) *mcpserver.Server {
	pipeline := rca.NewPipeline(engineQuery{engine: a.ai.be.Query, principal: principal}, a.ai.be.Audit)
	synth := rca.NewSynthesizer(a.ai.be.Model)
	return mcpserver.New(principal.TenantID, pipeline, synth, a.ai.rate, a.ai.be.Audit, a.ai.be.MCPIdentity)
}

// synthesize renders a grounded answer from gathered evidence: with no evidence it is
// "insufficient evidence" (no guess); with a model configured the synthesizer reasons
// over the cited evidence behind the redact+refuse boundary; without one the answer is
// the cited evidence itself (air-gapped default).
func (a *API) synthesize(r *http.Request, ev rca.Evidence) aiAnswer {
	synth := rca.NewSynthesizer(a.ai.be.Model)
	ans, err := synth.Answer(r.Context(), ev)
	if err != nil || (!ans.Sufficient && len(ev.Items) == 0) {
		return aiAnswer{Text: "insufficient evidence to answer", Citations: nil, Sufficient: false, Grounded: false}
	}
	// Stable citation order for a deterministic response body.
	cites := append([]string(nil), ans.Citations...)
	sort.Strings(cites)
	return aiAnswer{Text: ans.Text, Citations: cites, Sufficient: ans.Sufficient, Grounded: len(cites) > 0}
}

// writeAIQueryError maps the query engine's coarse errors to problem+json. The errors
// are intentionally coarse (the engine does not distinguish out-of-scope from
// not-found), so the mapping preserves that: a forbidden surface is 403, a malformed
// spec is 400, an over-budget/backpressure/deadline failure is 429/503.
func (a *API) writeAIQueryError(w http.ResponseWriter, err error) {
	switch {
	case isQueryErr(err, query.ErrForbidden):
		a.writeProblem(w, problemForbiddenAI())
	case isQueryErr(err, query.ErrMalformed):
		a.writeError(w, errStatus(http.StatusBadRequest, "malformed query"))
	case isQueryErr(err, query.ErrCostExceeded):
		a.writeError(w, errStatus(http.StatusBadRequest, "query cost guard exceeded"))
	case isQueryErr(err, query.ErrRejected):
		a.writeError(w, errStatus(http.StatusTooManyRequests, "query rejected (backpressure)"))
	case isQueryErr(err, query.ErrDeadline):
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "query deadline exceeded"))
	default:
		a.writeError(w, err)
	}
}

// writeMCPCallError maps the MCP server's errors to problem+json.
func (a *API) writeMCPCallError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, mcpserver.ErrRateLimited):
		a.writeError(w, errStatus(http.StatusTooManyRequests, "rate limit exceeded"))
	case errors.Is(err, mcpserver.ErrOutOfScope):
		a.writeProblem(w, problemForbiddenAI())
	case strings.Contains(err.Error(), "unknown or non-read-only tool"):
		a.writeError(w, errStatus(http.StatusNotFound, "unknown or non-read-only tool"))
	default:
		a.writeError(w, err)
	}
}

// isQueryErr reports whether err is (or wraps) the given query sentinel.
func isQueryErr(err, target error) bool { return errors.Is(err, target) }

// problemForbiddenAI is the coarse 403 the AI surface returns for an out-of-scope read
// (an RBAC-denied surface or a cross-tenant MCP call). It deliberately does not reveal
// WHY (out-of-scope vs not-found), matching the query layer's coarse-error contract so
// a caller cannot infer the shape of data it may not see.
func problemForbiddenAI() *problem.Problem {
	return problem.New(http.StatusForbidden, "forbidden: out of scope for this principal")
}
