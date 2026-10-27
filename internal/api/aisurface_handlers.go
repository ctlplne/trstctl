// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/mcpserver"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/query"
	"trstctl.com/trstctl/internal/rca"
)

// This file holds the HTTP handlers for the served AI/RCA/NL-query/MCP surface
// (SURFACE-003). Each handler resolves the AUTHENTICATED principal (guard already ran
// and bound it in the context), builds the rca pipeline/synthesizer or MCP server
// scoped to that principal, and answers ONLY from the caller's tenant. Every model
// egress (when a model is configured) goes through aimodel.Adapter.Reason inside the
// synthesizer, which redacts + refuses on residual entropy (AN-8). AI/RCA routes are
// read-only; MCP write tools appear only when explicitly enabled and execute by
// re-entering the served REST router.

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

// Questions are interpreted by query.PlanQuestion: a compositional grammar over
// certificates, ownership, crypto assets and graph inventories. Its typed plan is
// answered exactly, with the interpretation stated; anything outside it is
// answered as scoped evidence marked insufficient. In model-off mode a pile of
// cited rows cannot prove an arbitrary natural-language claim.

// mentionsCertificateExpiry recognises an expiry question the planner could not
// read, so the caller is told the form that works instead of getting evidence.
func mentionsCertificateExpiry(question string) bool {
	q := strings.ToLower(question)
	return (strings.Contains(q, "certificate") || strings.Contains(q, "certs")) && strings.Contains(q, "expir")
}

// aiAnswer is a grounded, cited answer (F75/F77). Text is grounded in Citations, which
// reference REAL records; Sufficient is false when there was no evidence (no guess).
type aiAnswer struct {
	Text       string   `json:"text"`
	Citations  []string `json:"citations"`
	Sufficient bool     `json:"sufficient"`
	Grounded   bool     `json:"grounded"`
}

// aiStatusResponse exposes the served AI runtime boundary without leaking secret-ish
// config. It reports whether the surface is mounted, whether a model is configured,
// which non-secret mode/provider/runtime is active, and what egress class applies.
type aiStatusResponse struct {
	Enabled             bool   `json:"enabled"`
	ModelConfigured     bool   `json:"model_configured"`
	ModelMode           string `json:"model_mode"`
	ModelName           string `json:"model_name,omitempty"`
	Runtime             string `json:"runtime,omitempty"`
	Provider            string `json:"provider,omitempty"`
	EndpointHost        string `json:"endpoint_host,omitempty"`
	Egress              string `json:"egress"`
	Redaction           string `json:"redaction"`
	ResidualRefusalGate bool   `json:"residual_refusal_gate"`
	// PIIEgress is the PRIVACY-005 personal-data egress posture: "redact"
	// (default-private), "block" (refuse on PII), or "allow" (operator consented).
	PIIEgress         string `json:"pii_egress"`
	MCPIdentity       string `json:"mcp_identity,omitempty"`
	MCPWriteTools     bool   `json:"mcp_write_tools"`
	RateMax           int    `json:"rate_max,omitempty"`
	RateWindowSeconds int    `json:"rate_window_seconds,omitempty"`
}

// rcaRequest is a grounded root-cause / NL question over the tenant's data (F77).
type rcaRequest struct {
	Subject  string `json:"subject"`
	Question string `json:"question"`
}

// mcpToolsResponse lists the exposed MCP tools (F78). read_only is true unless the
// explicit guarded write-tool opt-in is active.
type mcpToolsResponse struct {
	Identity string   `json:"identity,omitempty"`
	ReadOnly bool     `json:"read_only"`
	Tools    []string `json:"tools"`
}

// mcpCallRequest invokes one MCP tool (F78). Read tools use Subject. The guarded
// certificate write tools act on a lifecycle identity (IdentityID, with an optional
// subject CSR and a reason) and are accepted only when explicitly enabled.
// REST-backed tools use path_params/query/body and are replayed through the served
// HTTP router so normal route guards remain authoritative.
type mcpCallRequest struct {
	Subject    string `json:"subject"`
	IdentityID string `json:"identity_id,omitempty"`
	CSRPem     string `json:"csr_pem,omitempty"`
	Reason     string `json:"reason,omitempty"`
	// AuthorityID, TTLSeconds and PreviousSerial named a direct CA issuance the
	// write tools no longer make; a call that still sends authority_id is refused
	// with the replacement, so it cannot be mistaken for a gated issuance.
	AuthorityID    string            `json:"authority_id,omitempty"`
	TTLSeconds     int64             `json:"ttl_seconds,omitempty"`
	PreviousSerial string            `json:"previous_serial,omitempty"`
	PathParams     map[string]string `json:"path_params,omitempty"`
	Query          map[string]string `json:"query,omitempty"`
	Body           json.RawMessage   `json:"body,omitempty"`
}

// mcpCallResponse is the grounded, cited tool result (F78).
type mcpCallResponse struct {
	Tool      string   `json:"tool"`
	Citations []string `json:"citations,omitempty"`
	Text      string   `json:"text"`
	// Outcome, IdentityID and ApprovalRequestID report a certificate write: queued
	// (the lifecycle transition is recorded and its CA call is in the outbox) or
	// proposed (dual control applies, and the write waits for a distinct approver
	// on the named approval request; nothing was executed).
	Outcome           string `json:"outcome,omitempty"`
	IdentityID        string `json:"identity_id,omitempty"`
	ApprovalRequestID string `json:"approval_request_id,omitempty"`
	// CertificatePEM, Serial and NotAfter carried the direct CA issuance result the
	// write tools no longer make; they are never set.
	CertificatePEM string    `json:"certificate_pem,omitempty"`
	Serial         string    `json:"serial,omitempty"`
	NotAfter       time.Time `json:"not_after,omitzero"`
}

// MCP certificate write outcomes.
const (
	mcpWriteQueued   = "queued"
	mcpWriteProposed = "proposed"
)

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

// aiStatus reports the AI runtime/model posture. It is intentionally available even
// when the AI surface itself is disabled: disabled is a valid, fail-closed posture the
// UI and operators need to see as data. The route is still authenticated/RBAC-gated by
// guard(), so it is not a public capability probe.
func (a *API) aiStatus(w http.ResponseWriter, _ *http.Request) {
	status := aiStatusResponse{
		Enabled:             a.ai != nil,
		ModelMode:           "off",
		Egress:              "none",
		Redaction:           "default-redactor",
		ResidualRefusalGate: true,
		PIIEgress:           "redact", // default-private (PRIVACY-005)
	}
	if a.ai == nil {
		a.writeJSON(w, http.StatusOK, status)
		return
	}
	model := a.ai.be.Model
	st := a.ai.be.ModelStatus
	if st.Mode != "" {
		status.ModelMode = st.Mode
	}
	status.Runtime = st.Runtime
	status.Provider = st.Provider
	status.EndpointHost = st.EndpointHost
	if st.Egress != "" {
		status.Egress = st.Egress
	}
	if st.PIIEgress != "" {
		status.PIIEgress = st.PIIEgress
	} else if model != nil {
		status.PIIEgress = model.PIIEgressMode()
	}
	status.ModelConfigured = model != nil && model.Available()
	status.ModelName = st.ModelName
	if status.ModelName == "" && status.ModelConfigured {
		status.ModelName = model.ModelName()
	}
	status.MCPIdentity = a.ai.be.MCPIdentity
	status.MCPWriteTools = a.ai.be.MCPWriteTools
	status.RateMax = a.ai.be.RateMax
	status.RateWindowSeconds = int(a.ai.be.RateWindow.Seconds())
	a.writeJSON(w, http.StatusOK, status)
}

// aiQuery answers a typed semantic/NL query over the tenant's own data surfaces (F75).
// It is read-only; despite being POST (the typed spec travels in the body) it mutates
// no state. The tenant + RBAC scope come from the authenticated principal: a surface
// the principal cannot read denies the whole query (ErrForbidden -> 403), and no row
// from another tenant is reachable (RLS + in-process log tenant drop). A question the
// planner reads is answered exactly from its typed plan; any other question returns
// the selected surfaces as scoped evidence marked insufficient.
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
	asOf := time.Now().UTC()
	plan, planned := query.PlanQuestion(req.Question, asOf)
	if !planned && mentionsCertificateExpiry(req.Question) {
		a.writeError(w, errStatus(http.StatusUnprocessableEntity, "For a certificate expiry window, ask 'Which certificates expire within 30 days?' (1 to 365 days)."))
		return
	}
	selected := map[query.Surface]bool{}
	spec := query.Spec{Limit: req.Limit}
	for _, name := range req.Surfaces {
		surf, ok := surfaceByName[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			a.writeError(w, errStatus(http.StatusBadRequest, "unknown surface: "+name))
			return
		}
		selected[surf] = true
		spec.Select = append(spec.Select, surf)
		if req.Subject != "" && !planned {
			if field, has := subjectFieldForSurface(surf); has {
				spec.Where = append(spec.Where, query.Predicate{Field: field, Op: query.OpEq, Value: req.Subject})
			}
		}
	}
	if planned {
		// The question needs these surfaces selected. Every selected surface is
		// still authorized; only the plan's focus surfaces are read.
		for _, need := range plan.Spec.Select {
			if !selected[need] {
				a.writeError(w, errStatus(http.StatusBadRequest, "select "+string(need)+" to answer this question"))
				return
			}
		}
		planSpec := plan.Spec
		planSpec.Select, planSpec.Limit = spec.Select, req.Limit
		spec = planSpec
	}

	res, err := a.ai.be.Query.Query(r.Context(), principal, spec)
	if err != nil {
		a.writeAIQueryError(w, err)
		return
	}
	var owners map[string]string
	if planned && plan.Kind == query.PlanCertificateOwners {
		if owners, err = a.ownerNames(r, principal, spec.Select); err != nil {
			a.writeAIQueryError(w, err)
			return
		}
	}

	// Build a grounded answer from the scoped rows (the same grounding the RCA path
	// uses): cite each row. A planned question is answered from its plan; otherwise,
	// when a model is configured, synthesize over the cited evidence with the
	// redact+refuse boundary. Without a model the answer IS the cited evidence.
	ev := rca.Evidence{Question: req.Question, Subject: req.Subject}
	for _, row := range res.Rows {
		ev.Items = append(ev.Items, rca.EvidenceItem{
			Citation: string(row.Surface) + "#" + recordID(row),
			Summary:  aimodel.DefaultRedactor(rowSummary(row)),
		})
	}
	var ans aiAnswer
	if planned {
		ans = plannedAnswer(plan, ev, res, owners, req.Subject != "")
	} else {
		// The typed surface/subject filters may gather useful evidence, but they
		// do not interpret arbitrary question text. Never label a raw evidence
		// list as a complete answer to an unplanned question.
		ans = a.synthesize(r, ev)
		ans.Sufficient = false
		ans.Text = "The question was not fully interpreted. These are scoped evidence records, not a complete answer.\n" + ans.Text
	}
	if err := a.auditAIQuery(r, principal.TenantID, req.Subject, plan, planned, res, ans); err != nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "AI query audit is unavailable; retry the question"))
		return
	}
	a.writeJSON(w, http.StatusOK, ans)
}

// ownerNames maps the tenant's owner IDs to names for an ownership answer. It is a
// second scoped query over the owners surface, under the same principal.
func (a *API) ownerNames(r *http.Request, principal authz.Principal, selected []query.Surface) (map[string]string, error) {
	res, err := a.ai.be.Query.Query(r.Context(), principal, query.Spec{Select: selected, Focus: []query.Surface{query.SurfaceOwners}})
	if err != nil {
		return nil, err
	}
	names := make(map[string]string, len(res.Rows))
	for _, row := range res.Rows {
		names[row.Columns["id"]] = row.Columns["name"]
	}
	return names, nil
}

// plannedAnswer renders a planned question's exact answer. It says what was
// answered, how many rows are shown, whether more exist, and cites every row.
func plannedAnswer(plan query.Plan, ev rca.Evidence, res *query.Result, owners map[string]string, subjectIgnored bool) aiAnswer {
	var b strings.Builder
	fmt.Fprintf(&b, "Interpreted as: %s.\n", plan.Interpretation)
	sufficient := !res.Truncated
	if res.Counted {
		fmt.Fprintf(&b, "Count: %d.\n", res.Count)
		sufficient = true
	}
	fmt.Fprintf(&b, "%d shown.\n", len(ev.Items))
	switch {
	case res.Truncated && res.Counted:
		b.WriteString("The count is exact; only the first matches are cited.\n")
	case res.Truncated && plan.Spec.Certificates != nil:
		b.WriteString("More matching certificates may exist. Page through the certificate inventory for the complete set.\n")
	case res.Truncated:
		b.WriteString("More matching records may exist. Raise the limit for the complete set.\n")
	}
	if subjectIgnored {
		b.WriteString("The subject filter applies only to questions that are not interpreted; this answer follows the question.\n")
	}
	cites := make([]string, 0, len(ev.Items))
	for i, item := range ev.Items {
		cites = append(cites, item.Citation)
		fmt.Fprintf(&b, "- [%s] %s", item.Citation, item.Summary)
		if owners != nil {
			ownerID := res.Rows[i].Columns["owner_id"]
			if name, ok := owners[ownerID]; ok && ownerID != "" {
				cites = append(cites, "owners#"+ownerID)
				fmt.Fprintf(&b, " owner=[owners#%s] %s", ownerID, aimodel.DefaultRedactor(name))
			} else {
				b.WriteString(" owner=none recorded")
			}
		}
		b.WriteString("\n")
	}
	return aiAnswer{Text: b.String(), Citations: cites, Sufficient: sufficient, Grounded: len(cites) > 0}
}

// auditAIQuery appends the tenant's durable record of an answered question. The
// plan's kind and clause kinds are recorded, never the values taken from the
// question. A successful answer without it is a false success for an enterprise
// investigation, so the answer is withheld when this fails.
func (a *API) auditAIQuery(r *http.Request, tenantID, subject string, plan query.Plan, planned bool, res *query.Result, ans aiAnswer) error {
	windowAfter, windowBefore := "", ""
	kind, clauses := "", []string{}
	if planned {
		kind, clauses = string(plan.Kind), append(clauses, plan.Clauses...)
		if f := plan.Spec.Certificates; f != nil && plan.ExpiryDays > 0 && f.ExpiresAfter != nil && f.ExpiresBefore != nil {
			windowAfter = f.ExpiresAfter.Format(time.RFC3339Nano)
			windowBefore = f.ExpiresBefore.Format(time.RFC3339Nano)
		}
	}
	payload, err := json.Marshal(struct {
		Subject      string   `json:"subject"`
		Rows         int      `json:"rows"`
		Citations    int      `json:"citations"`
		Grounded     bool     `json:"grounded"`
		Sufficient   bool     `json:"sufficient"`
		ExpiryDays   int      `json:"expiry_days"`
		WindowAfter  string   `json:"window_after"`
		WindowBefore string   `json:"window_before"`
		Truncated    bool     `json:"truncated"`
		Plan         string   `json:"plan"`
		Clauses      []string `json:"clauses"`
		Count        int      `json:"count"`
		Counted      bool     `json:"counted"`
	}{subject, len(res.Rows), len(ans.Citations), ans.Grounded, ans.Sufficient, plan.ExpiryDays, windowAfter, windowBefore, res.Truncated,
		kind, clauses, res.Count, res.Counted})
	if err != nil {
		return err
	}
	return auditsink.EmitVersioned(r.Context(), a.ai.be.Audit, nil, "ai.query.answered", tenantID, 3, payload)
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

// mcpTools lists the MCP tools an external AI agent may call (F78). The list is built
// from an MCP server bound to the caller's tenant. By default it exposes only
// investigation tools and reports read_only=true; when guarded write tools are
// explicitly enabled it reports read_only=false.
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

// mcpCall invokes one MCP tool, scoped to the caller's tenant via SF.7. Investigation
// tools are grounded/cited; REST-backed tools re-enter the served router with the
// original authentication headers. Unknown tools are a 404; a cross-tenant request can
// never occur because the tenant is the principal's.
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
	if rt, ok := srv.RESTTool(tool); ok {
		a.mcpCallREST(w, r, principal, tool, rt, req)
		return
	}
	if srv.IsWriteTool(tool) {
		a.mcpCallWrite(w, r, principal, tool, req)
		return
	}
	// The caller key for rate limiting is the authenticated subject, so one principal's
	// enumeration cannot exhaust another's budget.
	res, err := srv.Call(r.Context(), principal.Subject, principal.TenantID, tool, req.Subject)
	if err != nil {
		a.writeMCPCallError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, mcpCallResponse{Tool: res.Tool, Citations: res.Citations, Text: res.Text})
}

// mcpCallREST executes one route-backed MCP tool by re-entering the served API router
// with the caller's original authentication headers. That keeps RBAC, tenant scoping,
// ABAC, CSRF, idempotency, per-tenant rate limiting, and handler validation in the
// normal route path; the MCP layer only translates tool arguments to an HTTP request.
func (a *API) mcpCallREST(w http.ResponseWriter, r *http.Request, principal authz.Principal, tool string, rt mcpserver.RESTTool, req mcpCallRequest) {
	if !a.ai.rate.Allow(principal.Subject + "|" + tool) {
		_ = auditsink.Emit(r.Context(), a.ai.be.Audit, nil, "mcp.tool.ratelimited", principal.TenantID,
			[]byte(fmt.Sprintf(`{"caller":%q,"tool":%q}`, principal.Subject, tool)))
		a.writeError(w, errStatus(http.StatusTooManyRequests, "rate limit exceeded"))
		return
	}
	path, err := mcpRESTPath(rt.Path, req.PathParams, req.Subject)
	if err != nil {
		a.writeError(w, err)
		return
	}
	path = mcpRESTURL(path, req.Query)
	body := mcpRESTBody(req.Body)
	inner, err := http.NewRequestWithContext(r.Context(), rt.Method, path, bytes.NewReader(body))
	if err != nil {
		a.writeError(w, err)
		return
	}
	copyMCPRESTHeaders(inner.Header, r.Header)
	if len(body) > 0 && inner.Header.Get("Content-Type") == "" {
		inner.Header.Set("Content-Type", "application/json")
	}

	rec := newMCPRESTRecorder()
	a.ServeHTTP(rec, inner)
	status := rec.status()
	_ = auditsink.Emit(r.Context(), a.ai.be.Audit, nil, "mcp.tool.rest", principal.TenantID,
		[]byte(fmt.Sprintf(`{"caller":%q,"tool":%q,"method":%q,"path":%q,"status":%d}`, principal.Subject, tool, rt.Method, rt.Path, status)))
	if status < 200 || status >= 300 {
		copyMCPRESTResponseHeaders(w.Header(), rec.Header())
		w.WriteHeader(status)
		_, _ = w.Write(rec.body.Bytes())
		return
	}
	a.writeJSON(w, status, mcpCallResponse{
		Tool:      tool,
		Text:      mcpRESTResponseSummary(rt, status),
		Citations: []string{rt.Method + " " + rt.Path},
	})
}

func mcpRESTResponseSummary(rt mcpserver.RESTTool, status int) string {
	summary := strings.TrimSpace(rt.Summary)
	if summary == "" {
		summary = strings.TrimSpace(rt.OperationID)
	}
	if summary == "" {
		summary = rt.Method + " " + rt.Path
	}
	return fmt.Sprintf("%s returned %d; full response body is omitted from MCP output", summary, status)
}

// mcpCallWrite runs the certificate write tools through the lifecycle gate (RA
// separation, the ABAC deny overlay, the default-deny policy and dual control):
// issue_certificate is the identity's transition to issued, and rotate_certificate
// takes the same issue decision, as the rotate playbook does, before the identity's
// renewal. The transition route records the approval request a dual-control
// tenant requires, so an issuance waiting for a distinct approver comes back as a
// proposal and executes only when the same call is made after the approval.
func (a *API) mcpCallWrite(w http.ResponseWriter, r *http.Request, principal authz.Principal, tool string, req mcpCallRequest) {
	if !a.ai.rate.Allow(principal.Subject + "|" + tool) {
		_ = auditsink.Emit(r.Context(), a.ai.be.Audit, nil, "mcp.tool.ratelimited", principal.TenantID,
			[]byte(fmt.Sprintf(`{"caller":%q,"tool":%q}`, principal.Subject, tool)))
		a.writeError(w, errStatus(http.StatusTooManyRequests, "rate limit exceeded"))
		return
	}
	identityID := strings.TrimSpace(req.IdentityID)
	if strings.TrimSpace(req.AuthorityID) != "" {
		a.writeError(w, errStatus(http.StatusBadRequest,
			tool+" acts on a lifecycle identity (identity_id) through the lifecycle gate; direct CA issuance is not available to MCP"))
		return
	}
	if identityID == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "identity_id is required for "+tool))
		return
	}
	transition := map[string]any{"to": string(orchestrator.StateIssued), "reason": req.Reason}
	if tool == "rotate_certificate" {
		// The renewal transition is outside the gate's issue/revoke/deploy set, but it
		// issues a certificate, so the issue decision is taken first.
		if err := a.gateOperatorTransition(r.Context(), principal, principal.TenantID, identityID, orchestrator.StateIssued); err != nil {
			a.writeError(w, err)
			return
		}
		transition["to"] = string(orchestrator.StateRenewing)
	} else if strings.TrimSpace(req.CSRPem) != "" {
		transition["subject_csr_pem"] = req.CSRPem
	}
	body, err := json.Marshal(transition)
	if err != nil {
		a.writeError(w, err)
		return
	}
	path, err := mcpRESTPath("/api/v1/identities/{id}/transitions", map[string]string{"id": identityID}, "")
	if err != nil {
		a.writeError(w, err)
		return
	}
	inner, err := http.NewRequestWithContext(r.Context(), http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		a.writeError(w, err)
		return
	}
	copyMCPRESTHeaders(inner.Header, r.Header)
	inner.Header.Set("Content-Type", "application/json")
	rec := newMCPRESTRecorder()
	a.ServeHTTP(rec, inner)
	status := rec.status()
	citations := []string{"POST /api/v1/identities/{id}/transitions", "identity:" + identityID}
	if approvalID, ok := mcpApprovalProposal(status, rec.body.Bytes()); ok {
		_ = auditsink.Emit(r.Context(), a.ai.be.Audit, nil, "mcp.tool.proposed", principal.TenantID,
			[]byte(fmt.Sprintf(`{"caller":%q,"tool":%q,"identity_id":%q,"approval_request_id":%q}`, principal.Subject, tool, identityID, approvalID)))
		a.writeJSON(w, http.StatusAccepted, mcpCallResponse{
			Tool: tool, Outcome: mcpWriteProposed, IdentityID: identityID, ApprovalRequestID: approvalID,
			Citations: append(citations, "approval_request:"+approvalID),
			Text: "dual control applies: the write waits for a distinct approver on approval request " + approvalID +
				"; nothing was executed. After it is approved, make the same call again with the same arguments and Idempotency-Key.",
		})
		return
	}
	if status < 200 || status >= 300 {
		copyMCPRESTResponseHeaders(w.Header(), rec.Header())
		w.WriteHeader(status)
		_, _ = w.Write(rec.body.Bytes())
		return
	}
	_ = auditsink.Emit(r.Context(), a.ai.be.Audit, nil, "mcp.tool.write", principal.TenantID,
		[]byte(fmt.Sprintf(`{"caller":%q,"tool":%q,"identity_id":%q,"transition":%q,"reason":%q}`, principal.Subject, tool, identityID, transition["to"], req.Reason)))
	text := "issuance of identity " + identityID + " is recorded and its CA call queued; the certificate is recorded when the call completes"
	if tool == "rotate_certificate" {
		text = "renewal of identity " + identityID + " is recorded and its CA call queued; the new certificate is deployed when the call completes"
	}
	a.writeJSON(w, http.StatusOK, mcpCallResponse{Tool: tool, Outcome: mcpWriteQueued, IdentityID: identityID, Citations: citations, Text: text})
}

// mcpApprovalProposal reports the approval request a dual-control refusal of the
// transition route names; that refusal is where the request was recorded.
func mcpApprovalProposal(status int, body []byte) (string, bool) {
	if status != http.StatusForbidden {
		return "", false
	}
	var p struct {
		Code              string `json:"code"`
		ApprovalRequestID string `json:"approval_request_id"`
	}
	if err := json.Unmarshal(body, &p); err != nil || p.Code != "identity_approval_required" || p.ApprovalRequestID == "" {
		return "", false
	}
	return p.ApprovalRequestID, true
}

// mcpExclusion names why a served route is never an MCP tool, or "". An agent never
// records an approval decision, and privileged certificate mutations reach MCP only
// through the lifecycle gate (issue_certificate and rotate_certificate), never
// through a route that mints, configures attestation trust or completes an issuance
// outside it.
func mcpExclusion(rt route) string {
	switch {
	case rt.approval:
		return "approval decision: an agent never approves or denies a dual-control request"
	case rt.mutation && rt.perm == authz.CertsIssue:
		return "privileged certificate mutation outside the lifecycle gate: MCP certificate writes use issue_certificate and rotate_certificate"
	}
	return ""
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
	opts := []mcpserver.Option{mcpserver.WithRESTTools(a.mcpRESTTools(), a.ai.be.MCPWriteTools)}
	if a.ai.be.MCPWriteTools {
		opts = append(opts, mcpserver.WithWriteTools())
	}
	return mcpserver.New(principal.TenantID, pipeline, synth, a.ai.rate, a.ai.be.Audit, a.ai.be.MCPIdentity, opts...)
}

func (a *API) mcpRESTTools() []mcpserver.RESTTool {
	routes := a.routes()
	tools := make([]mcpserver.RESTTool, 0, len(routes))
	for _, rt := range routes {
		if !mcpRESTToolCandidate(rt) {
			continue
		}
		tools = append(tools, mcpserver.RESTTool{
			Method:            rt.method,
			Path:              rt.path,
			OperationID:       rt.opID,
			Summary:           rt.summary,
			Permission:        string(rt.perm),
			PublicRationale:   publicRationaleForRoute(rt),
			Mutation:          rt.mutation,
			SensitiveResponse: rt.sensitiveResponse,
		})
	}
	return tools
}

func mcpRESTToolCandidate(rt route) bool {
	if rt.opID == "" || rt.perm == "" || mcpExclusion(rt) != "" {
		return false
	}
	if rt.sensitiveResponse {
		return false
	}
	if !strings.HasPrefix(rt.path, "/api/v1/") {
		return false
	}
	if strings.HasPrefix(rt.path, "/api/v1/mcp/") {
		return false
	}
	return true
}

func mcpRESTPath(template string, params map[string]string, subject string) (string, error) {
	names := mcpPathParamNames(template)
	path := template
	for _, rawName := range names {
		name := strings.TrimSuffix(rawName, "...")
		value := strings.TrimSpace(params[name])
		if value == "" {
			value = strings.TrimSpace(params[rawName])
		}
		if value == "" && len(names) == 1 {
			value = strings.TrimSpace(subject)
		}
		if value == "" {
			return "", errStatus(http.StatusBadRequest, "path parameter "+name+" is required")
		}
		path = strings.ReplaceAll(path, "{"+rawName+"}", url.PathEscape(value))
	}
	return path, nil
}

func mcpPathParamNames(template string) []string {
	var names []string
	rest := template
	for {
		start := strings.IndexByte(rest, '{')
		if start < 0 {
			return names
		}
		rest = rest[start+1:]
		end := strings.IndexByte(rest, '}')
		if end < 0 {
			return names
		}
		name := strings.TrimSpace(rest[:end])
		if name != "" {
			names = append(names, name)
		}
		rest = rest[end+1:]
	}
}

func mcpRESTURL(path string, query map[string]string) string {
	vals := url.Values{}
	for k, v := range query {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		vals.Set(k, strings.TrimSpace(v))
	}
	if len(vals) == 0 {
		return path
	}
	return path + "?" + vals.Encode()
}

func mcpRESTBody(raw json.RawMessage) []byte {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	return append([]byte(nil), raw...)
}

func copyMCPRESTHeaders(dst, src http.Header) {
	for k, vals := range src {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func copyMCPRESTResponseHeaders(dst, src http.Header) {
	for k, vals := range src {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

type mcpRESTRecorder struct {
	code   int
	header http.Header
	body   bytes.Buffer
}

func newMCPRESTRecorder() *mcpRESTRecorder {
	return &mcpRESTRecorder{header: http.Header{}}
}

func (r *mcpRESTRecorder) Header() http.Header { return r.header }

func (r *mcpRESTRecorder) WriteHeader(code int) {
	if r.code == 0 {
		r.code = code
	}
}

func (r *mcpRESTRecorder) Write(p []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	return r.body.Write(p)
}

func (r *mcpRESTRecorder) status() int {
	if r.code == 0 {
		return http.StatusOK
	}
	return r.code
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
