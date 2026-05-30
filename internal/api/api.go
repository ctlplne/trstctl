package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"certctl.io/certctl/internal/api/problem"
	"certctl.io/certctl/internal/audit"
	"certctl.io/certctl/internal/auth"
	"certctl.io/certctl/internal/authz"
	"certctl.io/certctl/internal/orchestrator"
	"certctl.io/certctl/internal/store"
)

const specPath = "/api/v1/openapi.json"

// API is the REST surface. It holds the read store, the idempotency recorder
// (AN-5), and the lifecycle orchestrator, resolves the tenant and principal per
// request, and enforces RBAC (F8) on every guarded route.
type API struct {
	store     *store.Store
	idem      *orchestrator.Idempotency
	orch      *orchestrator.Orchestrator
	tenantFn  func(*http.Request) (string, error)
	roles     *authz.Registry
	principal func(*http.Request) (authz.Principal, error)
	audit     *audit.Service
	mux       *http.ServeMux
	spec      *Document
}

// Option configures an API.
type Option func(*config)

type config struct {
	customRoles []authz.Role
	principalFn func(*http.Request) (authz.Principal, error)
	audit       *audit.Service
}

// WithAudit wires the audit-log service that backs the /api/v1/audit endpoints.
func WithAudit(svc *audit.Service) Option {
	return func(c *config) { c.audit = svc }
}

// WithRoles registers custom (tenant-defined) roles alongside the built-ins.
func WithRoles(roles ...authz.Role) Option {
	return func(c *config) { c.customRoles = append(c.customRoles, roles...) }
}

// WithPrincipalResolver overrides how the caller's principal (tenant, subject,
// role grants) is resolved from a request — the seam where OIDC/token auth
// (S3.6) plugs in. The default reads request headers.
func WithPrincipalResolver(fn func(*http.Request) (authz.Principal, error)) Option {
	return func(c *config) { c.principalFn = fn }
}

// New builds the API over its dependencies and wires the routes. The static
// OpenAPI document is built once from the route registry. The dependencies may
// be nil when only the spec is needed (e.g. for documentation tooling).
func New(st *store.Store, idem *orchestrator.Idempotency, orch *orchestrator.Orchestrator, opts ...Option) *API {
	cfg := &config{}
	for _, o := range opts {
		o(cfg)
	}
	reg := authz.NewRegistry(cfg.customRoles...)
	a := &API{store: st, idem: idem, orch: orch, tenantFn: tenantFromHeader, roles: reg, audit: cfg.audit}
	a.principal = cfg.principalFn
	if a.principal == nil {
		a.principal = a.resolvePrincipal
	}
	mux := http.NewServeMux()
	for _, r := range a.routes() {
		mux.HandleFunc(r.method+" "+r.path, a.guard(r.perm, r.handler))
	}
	mux.HandleFunc("/", a.notFound)
	a.mux = mux
	a.spec = buildSpec(a.routes())
	return a
}

// ServeHTTP implements http.Handler.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.mux.ServeHTTP(w, r) }

// Route is a served (method, path) pair, exposed so documentation tooling and
// tests can confirm the spec covers every route.
type Route struct {
	Method string
	Path   string
}

// Routes returns the served routes.
func (a *API) Routes() []Route {
	rs := a.routes()
	out := make([]Route, 0, len(rs))
	for _, r := range rs {
		out = append(out, Route{Method: r.method, Path: r.path})
	}
	return out
}

// param is an OpenAPI query parameter descriptor.
type param struct {
	name string
	typ  string
	desc string
}

// route binds an HTTP method+path to a handler and carries the metadata used to
// generate the OpenAPI document and to enforce RBAC.
type route struct {
	method      string
	path        string
	opID        string
	summary     string
	handler     http.HandlerFunc
	pathParams  []string
	query       []param
	reqSchema   string
	resSchema   string
	successCode string
	mutation    bool
	perm        authz.Permission // required permission; "" means public
}

func (a *API) routes() []route {
	page := []param{
		{name: "limit", typ: "integer", desc: "maximum items per page (1-100, default 20)"},
		{name: "cursor", typ: "string", desc: "opaque pagination cursor from a prior page"},
	}
	certQuery := []param{
		{name: "limit", typ: "integer", desc: "maximum items per page (1-100, default 20)"},
		{name: "cursor", typ: "string", desc: "opaque pagination cursor from a prior page"},
		{name: "expiring_before", typ: "string", desc: "RFC3339; return only certificates expiring before this time"},
	}
	auditQuery := []param{
		{name: "type", typ: "string", desc: "comma-separated event types to include"},
		{name: "since", typ: "string", desc: "RFC3339 inclusive lower time bound"},
		{name: "until", typ: "string", desc: "RFC3339 inclusive upper time bound"},
		{name: "as_of", typ: "integer", desc: "point-in-time: only events with sequence <= this"},
		{name: "q", typ: "string", desc: "substring match on event type or data"},
		{name: "limit", typ: "integer", desc: "maximum records to return"},
	}
	return []route{
		{method: "POST", path: "/api/v1/owners", opID: "createOwner", summary: "Create an owner", handler: a.createOwner, reqSchema: "OwnerRequest", resSchema: "Owner", successCode: "201", mutation: true, perm: authz.OwnersWrite},
		{method: "GET", path: "/api/v1/owners", opID: "listOwners", summary: "List owners", handler: a.listOwners, query: page, resSchema: "OwnerList", successCode: "200", perm: authz.OwnersRead},
		{method: "GET", path: "/api/v1/owners/{id}", opID: "getOwner", summary: "Get an owner", handler: a.getOwner, pathParams: []string{"id"}, resSchema: "Owner", successCode: "200", perm: authz.OwnersRead},
		{method: "PUT", path: "/api/v1/owners/{id}", opID: "updateOwner", summary: "Replace an owner", handler: a.updateOwner, pathParams: []string{"id"}, reqSchema: "OwnerRequest", resSchema: "Owner", successCode: "200", mutation: true, perm: authz.OwnersWrite},
		{method: "DELETE", path: "/api/v1/owners/{id}", opID: "deleteOwner", summary: "Delete an owner", handler: a.deleteOwner, pathParams: []string{"id"}, successCode: "204", mutation: true, perm: authz.OwnersWrite},

		{method: "POST", path: "/api/v1/issuers", opID: "createIssuer", summary: "Create an issuer", handler: a.createIssuer, reqSchema: "IssuerRequest", resSchema: "Issuer", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "GET", path: "/api/v1/issuers", opID: "listIssuers", summary: "List issuers", handler: a.listIssuers, query: page, resSchema: "IssuerList", successCode: "200", perm: authz.IssuersRead},
		{method: "GET", path: "/api/v1/issuers/{id}", opID: "getIssuer", summary: "Get an issuer", handler: a.getIssuer, pathParams: []string{"id"}, resSchema: "Issuer", successCode: "200", perm: authz.IssuersRead},

		{method: "POST", path: "/api/v1/identities", opID: "createIdentity", summary: "Create an identity", handler: a.createIdentity, reqSchema: "IdentityRequest", resSchema: "Identity", successCode: "201", mutation: true, perm: authz.IdentitiesWrite},
		{method: "GET", path: "/api/v1/identities", opID: "listIdentities", summary: "List identities", handler: a.listIdentities, query: page, resSchema: "IdentityList", successCode: "200", perm: authz.IdentitiesRead},
		{method: "GET", path: "/api/v1/identities/{id}", opID: "getIdentity", summary: "Get an identity", handler: a.getIdentity, pathParams: []string{"id"}, resSchema: "Identity", successCode: "200", perm: authz.IdentitiesRead},
		{method: "POST", path: "/api/v1/identities/{id}/transitions", opID: "transitionIdentity", summary: "Apply a lifecycle transition", handler: a.transitionIdentity, pathParams: []string{"id"}, reqSchema: "TransitionRequest", resSchema: "Identity", successCode: "200", mutation: true, perm: authz.IdentitiesWrite},

		{method: "POST", path: "/api/v1/certificates", opID: "ingestCertificate", summary: "Ingest a certificate into the inventory", handler: a.ingestCertificate, reqSchema: "CertificateIngest", resSchema: "Certificate", successCode: "201", mutation: true, perm: authz.CertsWrite},
		{method: "GET", path: "/api/v1/certificates", opID: "listCertificates", summary: "Query the certificate inventory", handler: a.listCertificates, query: certQuery, resSchema: "CertificateList", successCode: "200", perm: authz.CertsRead},
		{method: "GET", path: "/api/v1/certificates/{id}", opID: "getCertificate", summary: "Get an inventoried certificate", handler: a.getCertificate, pathParams: []string{"id"}, resSchema: "Certificate", successCode: "200", perm: authz.CertsRead},

		{method: "GET", path: "/api/v1/audit/events", opID: "searchAudit", summary: "Query the audit log", handler: a.searchAudit, query: auditQuery, resSchema: "AuditEventList", successCode: "200", perm: authz.AuditRead},
		{method: "GET", path: "/api/v1/audit/export", opID: "exportAudit", summary: "Export a signed audit evidence bundle", handler: a.exportAudit, query: auditQuery, resSchema: "AuditBundle", successCode: "200", perm: authz.AuditRead},

		{method: "GET", path: "/api/v1/graph", opID: "getGraph", summary: "Get the credential graph", handler: a.getGraph, successCode: "200", perm: authz.GraphRead},
		{method: "GET", path: "/api/v1/graph/reachable/{id}", opID: "graphReachable", summary: "Nodes reachable from a node (reachability query)", handler: a.graphReachable, pathParams: []string{"id"}, successCode: "200", perm: authz.GraphRead},
		{method: "GET", path: "/api/v1/graph/blast-radius/{id}", opID: "graphBlastRadius", summary: "Blast radius of compromising a node", handler: a.graphBlastRadius, pathParams: []string{"id"}, successCode: "200", perm: authz.GraphRead},
		{method: "POST", path: "/api/v1/graph/query", opID: "graphQuery", summary: "Run a Cypher-style graph query", handler: a.graphQuery, successCode: "200", perm: authz.GraphRead},

		{method: "GET", path: "/api/v1/risk/credentials", opID: "listRiskScores", summary: "Rank credentials by composite risk score", handler: a.listRiskScores, successCode: "200", perm: authz.RiskRead},

		{method: "GET", path: specPath, opID: "getOpenAPISpec", summary: "OpenAPI 3.1 specification", handler: a.openapiHandler, successCode: "200"},
	}
}

// tenantFromHeader resolves the tenant from the X-Tenant-ID header. It is a
// placeholder for the auth-derived tenant (OIDC/mTLS/API token), which a later
// sprint substitutes via a custom resolver.
func tenantFromHeader(r *http.Request) (string, error) {
	t := r.Header.Get("X-Tenant-ID")
	if t == "" {
		return "", errors.New("missing X-Tenant-ID")
	}
	return t, nil
}

// ctxKey is the type for request-context keys owned by this package.
type ctxKey int

const principalCtxKey ctxKey = iota

// tenant returns the tenant the request operates in. For a guarded route the
// authenticated principal (placed in the context by guard) is authoritative —
// this is what lets a bearer API token carry its own tenant; otherwise it falls
// back to the tenant header (e.g. the public spec route has no principal).
func (a *API) tenant(r *http.Request) (string, bool) {
	if p, ok := r.Context().Value(principalCtxKey).(authz.Principal); ok && p.TenantID != "" {
		return p.TenantID, true
	}
	t, err := a.tenantFn(r)
	return t, err == nil
}

// resolvePrincipal is the default principal resolver: an Authorization: Bearer
// certctl API token authenticates by its hash (carrying its own tenant and
// scopes); otherwise the request is resolved from headers (the dev/test path
// that OIDC/SAML session cookies will replace).
func (a *API) resolvePrincipal(r *http.Request) (authz.Principal, error) {
	if tok := bearerToken(r); strings.HasPrefix(tok, auth.TokenPrefix) {
		if a.store == nil {
			return authz.Principal{}, errors.New("api: no token store configured")
		}
		hash, err := auth.HashAPIToken(tok)
		if err != nil {
			return authz.Principal{}, err
		}
		rec, err := a.store.LookupAPITokenByHash(r.Context(), hash)
		if err != nil {
			return authz.Principal{}, errors.New("api: unknown api token")
		}
		if rec.ExpiresAt != nil && !rec.ExpiresAt.After(time.Now()) {
			return authz.Principal{}, errors.New("api: expired api token")
		}
		return auth.APIToken{TenantID: rec.TenantID, Subject: rec.Subject, Scopes: rec.Scopes}.Principal(), nil
	}
	return principalFromHeaders(a.roles)(r)
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// principalFromHeaders resolves the caller's principal from request headers — a
// placeholder for auth-derived claims (S3.6). X-Roles is a comma-separated list
// of role names (resolved against the registry); X-Role-Project is the project
// those roles are granted in ("" = tenant-wide).
func principalFromHeaders(reg *authz.Registry) func(*http.Request) (authz.Principal, error) {
	return func(r *http.Request) (authz.Principal, error) {
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			return authz.Principal{}, errors.New("missing X-Tenant-ID")
		}
		scope := authz.Scope{TenantID: tenantID, Project: r.Header.Get("X-Role-Project")}
		var grants []authz.Grant
		for _, name := range strings.Split(r.Header.Get("X-Roles"), ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if role, ok := reg.Role(name); ok {
				grants = append(grants, authz.Grant{Role: role, Scope: scope})
			}
		}
		return authz.Principal{TenantID: tenantID, Subject: r.Header.Get("X-Subject"), Grants: grants}, nil
	}
}

// guard enforces the route's required permission (AN: RBAC/F8) before invoking
// the handler. A route with no permission ("") is public. Denials are
// problem+json: 401 when the principal can't be resolved, 403 when the principal
// lacks the permission in the target scope (from X-Project).
func (a *API) guard(perm authz.Permission, h http.HandlerFunc) http.HandlerFunc {
	if perm == "" {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		principal, err := a.principal(r)
		if err != nil {
			a.writeProblem(w, problemUnauthorized())
			return
		}
		target := authz.Scope{TenantID: principal.TenantID, Project: r.Header.Get("X-Project")}
		if !principal.Can(perm, target) {
			a.writeProblem(w, problem.New(http.StatusForbidden, "forbidden: requires "+string(perm)))
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), principalCtxKey, principal)))
	}
}

// cachedResponse is the response envelope stored by the idempotency recorder so
// a replayed key returns the identical status and body.
type cachedResponse struct {
	Status int             `json:"s"`
	Body   json.RawMessage `json:"b"`
}

// mutate runs a mutating operation under an idempotency key (AN-5): a replay
// returns the original response without re-executing. It requires a tenant and a
// non-empty key, both surfaced as problem+json.
func (a *API) mutate(w http.ResponseWriter, r *http.Request, idempotencyKey string, fn func(ctx context.Context, tenantID string) (int, any, error)) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problem.New(http.StatusUnauthorized, "missing or invalid tenant"))
		return
	}
	if idempotencyKey == "" {
		a.writeProblem(w, problem.New(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}

	raw, err := a.idem.Do(r.Context(), tenantID, idempotencyKey, func(ctx context.Context) ([]byte, error) {
		status, body, ferr := fn(ctx, tenantID)
		if ferr != nil {
			return nil, ferr
		}
		bodyJSON := json.RawMessage("null")
		if body != nil {
			bj, mErr := json.Marshal(body)
			if mErr != nil {
				return nil, mErr
			}
			bodyJSON = bj
		}
		return json.Marshal(cachedResponse{Status: status, Body: bodyJSON})
	})
	if err != nil {
		a.writeError(w, err)
		return
	}

	var c cachedResponse
	if err := json.Unmarshal(raw, &c); err != nil {
		a.writeError(w, err)
		return
	}
	if c.Status == http.StatusNoContent {
		w.WriteHeader(c.Status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c.Status)
	_, _ = w.Write(c.Body)
}

// apiError lets a handler choose the problem status for a domain failure.
type apiError struct {
	status int
	detail string
	ext    map[string]any
}

func (e *apiError) Error() string { return e.detail }

func errStatus(status int, detail string) *apiError { return &apiError{status: status, detail: detail} }

// writeError maps an error to a problem+json response.
func (a *API) writeError(w http.ResponseWriter, err error) {
	var ae *apiError
	switch {
	case errors.As(err, &ae):
		p := problem.New(ae.status, ae.detail)
		for k, v := range ae.ext {
			p = p.WithExtension(k, v)
		}
		a.writeProblem(w, p)
	case store.IsNotFound(err):
		a.writeProblem(w, problem.New(http.StatusNotFound, "resource not found"))
	case errors.Is(err, orchestrator.ErrInvalidTransition):
		p := problem.New(http.StatusConflict, err.Error())
		var te *orchestrator.TransitionError
		if errors.As(err, &te) {
			p = p.WithExtension("from", string(te.From)).WithExtension("to", string(te.To))
		}
		a.writeProblem(w, p)
	default:
		a.writeProblem(w, problem.New(http.StatusInternalServerError, "internal error"))
	}
}

func (a *API) writeProblem(w http.ResponseWriter, p *problem.Problem) { _ = p.Write(w) }

func problemUnauthorized() *problem.Problem {
	return problem.New(http.StatusUnauthorized, "missing or invalid tenant")
}

func (a *API) writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		a.writeProblem(w, problem.New(http.StatusInternalServerError, "failed to encode response"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func (a *API) notFound(w http.ResponseWriter, _ *http.Request) {
	a.writeProblem(w, problem.New(http.StatusNotFound, "no such resource"))
}

func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return errors.New("request body is required")
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

// pageParams parses cursor-pagination query parameters, returning the page size
// and the keyset start id.
func (a *API) pageParams(r *http.Request) (limit int, after string, err error) {
	limit = 20
	if s := r.URL.Query().Get("limit"); s != "" {
		n, e := strconv.Atoi(s)
		if e != nil || n < 1 || n > 100 {
			return 0, "", errors.New("limit must be an integer between 1 and 100")
		}
		limit = n
	}
	after = store.ZeroUUID
	if c := r.URL.Query().Get("cursor"); c != "" {
		id, e := decodeCursor(c)
		if e != nil {
			return 0, "", errors.New("invalid cursor")
		}
		after = id
	}
	return limit, after, nil
}

func encodeCursor(id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(id))
}

func decodeCursor(c string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return "", err
	}
	if len(b) != 36 { // a UUID in canonical text form
		return "", errors.New("cursor is not a valid id")
	}
	return string(b), nil
}
