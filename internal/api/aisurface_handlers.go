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

// mcpCallRequest invokes one MCP tool (F78). Read tools use Subject. Guarded write
// certificate convenience tools use the certificate fields and are accepted only when
// explicitly enabled. REST-backed tools use path_params/query/body and are replayed
// through the served HTTP router so normal route guards remain authoritative.
type mcpCallRequest struct {
	Subject        string            `json:"subject"`
	AuthorityID    string            `json:"authority_id,omitempty"`
	CSRPem         string            `json:"csr_pem,omitempty"`
	TTLSeconds     int64             `json:"ttl_seconds,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	PreviousSerial string            `json:"previous_serial,omitempty"`
	PathParams     map[string]string `json:"path_params,omitempty"`
	Query          map[string]string `json:"query,omitempty"`
	Body           json.RawMessage   `json:"body,omitempty"`
}

// mcpCallResponse is the grounded, cited tool result (F78).
type mcpCallResponse struct {
	Tool           string    `json:"tool"`
	Citations      []string  `json:"citations,omitempty"`
	Text           string    `json:"text"`
	CertificatePEM string    `json:"certificate_pem,omitempty"`
	Serial         string    `json:"serial,omitempty"`
	NotAfter       time.Time `json:"not_after,omitempty"`
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
	text := strings.TrimSpace(rec.body.String())
	if text == "" {
		text = fmt.Sprintf("%s %s returned %d", rt.Method, rt.Path, status)
	}
	if legacyMCPCertificateTool(tool) {
		var issued CAIssuedLeaf
		if err := json.Unmarshal(rec.body.Bytes(), &issued); err == nil {
			text := "issued certificate serial " + issued.Serial
			if tool == "rotate_certificate" {
				text = "rotated certificate " + strings.TrimSpace(req.PreviousSerial) + " to serial " + issued.Serial
			}
			_ = auditsink.Emit(r.Context(), a.ai.be.Audit, nil, "mcp.tool.write", principal.TenantID,
				[]byte(fmt.Sprintf(`{"caller":%q,"tool":%q,"authority_id":%q,"serial":%q,"reason":%q}`, principal.Subject, tool, strings.TrimSpace(req.AuthorityID), issued.Serial, req.Reason)))
			a.writeJSON(w, status, mcpCallResponse{
				Tool:           tool,
				Text:           text,
				Citations:      []string{rt.Method + " " + rt.Path, "ca_issued_cert:" + issued.Serial},
				CertificatePEM: issued.CertificatePEM,
				Serial:         issued.Serial,
				NotAfter:       issued.NotAfter,
			})
			return
		}
	}
	a.writeJSON(w, status, mcpCallResponse{
		Tool:      tool,
		Text:      text,
		Citations: []string{rt.Method + " " + rt.Path},
	})
}

func legacyMCPCertificateTool(tool string) bool {
	return tool == "issue_certificate" || tool == "rotate_certificate"
}

// mcpCallWrite keeps the historical certificate convenience tool names working by
// translating them to the served CA issuance route. The actual permission check,
// issuer scoping, idempotency, request validation, and mutation all happen inside the
// normal REST handler reached through mcpCallREST.
func (a *API) mcpCallWrite(w http.ResponseWriter, r *http.Request, principal authz.Principal, tool string, req mcpCallRequest) {
	if tool == "rotate_certificate" && strings.TrimSpace(req.PreviousSerial) == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "previous_serial is required for rotate_certificate"))
		return
	}
	req.PathParams = copyStringMap(req.PathParams)
	if req.PathParams == nil {
		req.PathParams = map[string]string{}
	}
	req.PathParams["id"] = strings.TrimSpace(req.AuthorityID)
	body, err := json.Marshal(caIssueLeafJSON{CSRPem: req.CSRPem, TTLSeconds: req.TTLSeconds})
	if err != nil {
		a.writeError(w, err)
		return
	}
	req.Body = body
	a.mcpCallREST(w, r, principal, tool, mcpserver.RESTTool{
		Method:      http.MethodPost,
		Path:        "/api/v1/ca/authorities/{id}/issue",
		OperationID: "issueHierarchyLeaf",
		Summary:     "Issue a leaf certificate from a served CA authority",
		Permission:  string(authz.CertsIssue),
		Mutation:    true,
	}, req)
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
			Method:          rt.method,
			Path:            rt.path,
			OperationID:     rt.opID,
			Summary:         rt.summary,
			Permission:      string(rt.perm),
			PublicRationale: publicRationaleForRoute(rt),
			Mutation:        rt.mutation,
		})
	}
	return tools
}

func mcpRESTToolCandidate(rt route) bool {
	if rt.opID == "" || rt.perm == "" {
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
