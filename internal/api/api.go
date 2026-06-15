package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trustctl.io/trustctl/internal/api/problem"
	"trustctl.io/trustctl/internal/audit"
	"trustctl.io/trustctl/internal/auth"
	"trustctl.io/trustctl/internal/authz"
	"trustctl.io/trustctl/internal/events"
	"trustctl.io/trustctl/internal/orchestrator"
	"trustctl.io/trustctl/internal/store"
)

const specPath = "/api/v1/openapi.json"

// BootstrapTokenIssuer mints one-time agent bootstrap tokens (S5.1) bound to the
// authorizing tenant (WIRE-003/AN-1). The web first-run wizard (S7.3) uses it to
// build the agent install command; the agent presents the token once to enroll,
// and the issued certificate is attributed to tenantID. The API depends only on
// this minimal interface so it never imports the enrollment authority's transport
// stack.
type BootstrapTokenIssuer interface {
	IssueBootstrapToken(ctx context.Context, tenantID string) (string, error)
}

// API is the REST surface. It holds the read store, the idempotency recorder
// (AN-5), and the lifecycle orchestrator, resolves the tenant and principal per
// request, and enforces RBAC (F8) on every guarded route.
type API struct {
	store         *store.Store
	idem          *orchestrator.Idempotency
	orch          *orchestrator.Orchestrator
	tenantFn      func(*http.Request) (string, error)
	roles         *authz.Registry
	principal     func(*http.Request) (authz.Principal, error)
	audit         *audit.Service
	auth          *AuthConfig
	agentTokens   BootstrapTokenIssuer
	agentEnroller BootstrapEnroller
	rateLimiter   RateLimiter
	gate          MutationGate
	approvals     ApprovalRecorder
	secrets       *secretsService // served secrets/identity surface (GAP-006); nil = not enabled
	mux           *http.ServeMux
	spec          *Document
}

// Option configures an API.
type Option func(*config)

type config struct {
	customRoles []authz.Role
	principalFn func(*http.Request) (authz.Principal, error)
	// principalFromReg is a resolver factory the test-only header resolver uses.
	// It is built against the API's role registry (so custom roles work) and the
	// real authenticated resolver (so test servers still accept bearer tokens and
	// sessions). It is referenced only from WithInsecureHeaderResolver, so it is
	// not linked into the production build. See WithInsecureHeaderResolver.
	principalFromReg func(reg *authz.Registry, fallback func(*http.Request) (authz.Principal, error)) func(*http.Request) (authz.Principal, error)
	audit            *audit.Service
	auth             *AuthConfig
	agentTokens      BootstrapTokenIssuer
	agentEnroller    BootstrapEnroller
	rateLimiter      RateLimiter
	gate             MutationGate
	approvals        ApprovalRecorder
	secrets          *secretsService
}

// WithAudit wires the audit-log service that backs the /api/v1/audit endpoints.
func WithAudit(svc *audit.Service) Option {
	return func(c *config) { c.audit = svc }
}

// WithRoles registers custom (tenant-defined) roles alongside the built-ins.
func WithRoles(roles ...authz.Role) Option {
	return func(c *config) { c.customRoles = append(c.customRoles, roles...) }
}

// WithAuth wires the browser OIDC login + session bridge used by the web UI
// (/auth/login, /auth/callback, /auth/me, /auth/logout). These are not core API
// operations, so they are not part of the route registry (or the OpenAPI spec).
func WithAuth(cfg AuthConfig) Option {
	return func(c *config) { c.auth = &cfg }
}

// WithAgentEnrollment wires the agent bootstrap-token issuer that backs
// POST /api/v1/agents/enrollment-tokens (the web wizard's "install an agent"
// step). When unset, that endpoint reports the capability is unavailable.
func WithAgentEnrollment(issuer BootstrapTokenIssuer) Option {
	return func(c *config) { c.agentTokens = issuer }
}

// WithPrincipalResolver overrides how the caller's principal (tenant, subject,
// role grants) is resolved from a request — the seam where OIDC/token auth
// (S3.6) plugs in. The default reads request headers.
func WithPrincipalResolver(fn func(*http.Request) (authz.Principal, error)) Option {
	return func(c *config) { c.principalFn = fn }
}

// RateLimiter sheds load per authenticated tenant (R2.3). Allow takes one unit of
// quota for tenantID; allowed is false when the tenant is over budget, with
// retryAfter indicating when to retry. The API depends only on this interface so
// it does not import the PostgreSQL-backed implementation (no datastore coupling).
type RateLimiter interface {
	Allow(ctx context.Context, tenantID string) (allowed bool, retryAfter time.Duration, err error)
}

// WithRateLimiter wires a per-tenant rate limiter onto the guarded routes. When
// unset, no rate limiting is applied.
func WithRateLimiter(rl RateLimiter) Option {
	return func(c *config) { c.rateLimiter = rl }
}

// WithMutationGate wires the served policy / RA-separation / dual-control gate onto
// the mutating lifecycle path (EXC-WIRE-03). When set, a served issue/deploy/revoke
// transition is denied unless the default-deny policy explicitly allows it, a
// privileged issue/revoke requires the certs:issue authority (the requester scope
// cannot self-issue), and — when dual control is enabled — a distinct-approver
// approval must be on record. The zero gate is a permissive no-op, so an unconfigured
// deployment keeps the prior served behavior. This closes SEC-002/SEC-005/CORRECT-003
// (the gate was library-only) and is the served half of the RED-004 defense.
func WithMutationGate(g MutationGate) Option {
	return func(c *config) { c.gate = g }
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
	a := &API{store: st, idem: idem, orch: orch, tenantFn: tenantFromHeader, roles: reg, audit: cfg.audit, auth: cfg.auth, agentTokens: cfg.agentTokens, agentEnroller: cfg.agentEnroller, rateLimiter: cfg.rateLimiter, gate: cfg.gate, approvals: cfg.approvals, secrets: cfg.secrets}
	// The default is the authenticated, fail-closed resolver (bearer token or OIDC
	// session, else unauthenticated). A custom resolver is honored when given; the
	// header-trusting resolver is reachable ONLY through its factory option
	// (test/dev), never by default — so production never trusts identity headers.
	switch {
	case cfg.principalFn != nil:
		a.principal = cfg.principalFn
	case cfg.principalFromReg != nil:
		a.principal = cfg.principalFromReg(reg, a.resolvePrincipal)
	default:
		a.principal = a.resolvePrincipal
	}
	mux := http.NewServeMux()
	for _, r := range a.routes() {
		mux.HandleFunc(r.method+" "+r.path, a.guard(r.perm, r.handler))
	}
	// The browser OIDC login + session bridge for the web UI (S7.2). These are
	// registered outside the route registry so they stay out of the CLI/OpenAPI
	// surface.
	if a.auth != nil {
		mux.HandleFunc("GET /auth/login", a.authLogin)
		mux.HandleFunc("GET /auth/callback", a.authCallback)
		mux.HandleFunc("GET /auth/me", a.authMe)
		mux.HandleFunc("POST /auth/logout", a.authLogout)
	}
	// Agent bootstrap enrollment (S5.1/F15). The one-time token authenticates the
	// request, so this route carries no RBAC permission and stays out of the
	// /api, CLI, and OpenAPI surfaces — the same treatment as the OIDC bridge.
	if a.agentEnroller != nil {
		mux.HandleFunc("POST /enroll/bootstrap", a.enrollBootstrap)
	}
	// Machine login (authmethod/F58): a workload presents a credential and receives a
	// scoped session. The credential authenticates the request, so this route carries
	// no RBAC permission — like the OIDC bridge and agent bootstrap, it stays out of
	// the route registry (and thus the OpenAPI/CLI surface). It is registered only when
	// the served secrets surface is wired; otherwise it fails closed in the handler.
	// The path is /api/v1/secrets/login (distinct from the browser OIDC /auth/login
	// bridge — this is the machine-identity login, not the human SSO).
	if a.secrets != nil {
		mux.HandleFunc("POST /api/v1/secrets/login", a.machineLogin)
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

// Routes returns the served routes. Paths are reported in their OpenAPI-template
// form: a Go ServeMux trailing-wildcard segment ("{name...}", which lets a path
// parameter span multiple segments) is normalized to the standard "{name}" the
// generated document uses, so doc-coverage tooling matches the published contract
// (the live mux still routes on the wildcard form).
func (a *API) Routes() []Route {
	rs := a.routes()
	out := make([]Route, 0, len(rs))
	for _, r := range rs {
		out = append(out, Route{Method: r.method, Path: openapiPath(r.path)})
	}
	return out
}

// openapiPath normalizes a route path to its OpenAPI-template form by reducing a
// trailing-wildcard segment ("{name...}") to "{name}". It is the single place that
// mapping lives, shared by Routes and buildSpec.
func openapiPath(p string) string { return strings.ReplaceAll(p, "...}", "}") }

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
		{method: "POST", path: "/api/v1/identities/{id}/approvals", opID: "approveIdentityAction", summary: "Approve a pending privileged action (dual control)", handler: a.approveIdentityAction, pathParams: []string{"id"}, reqSchema: "ApprovalRequest", resSchema: "Approval", successCode: "200", mutation: true, perm: authz.CertsIssue},

		{method: "POST", path: "/api/v1/certificates", opID: "ingestCertificate", summary: "Ingest a certificate into the inventory", handler: a.ingestCertificate, reqSchema: "CertificateIngest", resSchema: "Certificate", successCode: "201", mutation: true, perm: authz.CertsWrite},
		{method: "GET", path: "/api/v1/certificates", opID: "listCertificates", summary: "Query the certificate inventory", handler: a.listCertificates, query: certQuery, resSchema: "CertificateList", successCode: "200", perm: authz.CertsRead},
		{method: "GET", path: "/api/v1/certificates/{id}", opID: "getCertificate", summary: "Get an inventoried certificate", handler: a.getCertificate, pathParams: []string{"id"}, resSchema: "Certificate", successCode: "200", perm: authz.CertsRead},

		{method: "POST", path: "/api/v1/profiles", opID: "createProfile", summary: "Create a certificate profile version", handler: a.createProfile, reqSchema: "ProfileRequest", resSchema: "Profile", successCode: "201", mutation: true, perm: authz.ProfilesWrite},
		{method: "GET", path: "/api/v1/profiles", opID: "listProfiles", summary: "List active certificate profiles", handler: a.listProfiles, resSchema: "ProfileList", successCode: "200", perm: authz.ProfilesRead},
		{method: "GET", path: "/api/v1/profiles/{name}/versions/{version}", opID: "getProfileVersion", summary: "Get a certificate-profile version", handler: a.getProfileVersion, pathParams: []string{"name", "version"}, resSchema: "Profile", successCode: "200", perm: authz.ProfilesRead},

		{method: "GET", path: "/api/v1/audit/events", opID: "searchAudit", summary: "Query the audit log", handler: a.searchAudit, query: auditQuery, resSchema: "AuditEventList", successCode: "200", perm: authz.AuditRead},
		{method: "GET", path: "/api/v1/audit/export", opID: "exportAudit", summary: "Export a signed audit evidence bundle", handler: a.exportAudit, query: auditQuery, resSchema: "AuditBundle", successCode: "200", perm: authz.AuditRead},

		{method: "GET", path: "/api/v1/graph", opID: "getGraph", summary: "Get the credential graph", handler: a.getGraph, successCode: "200", perm: authz.GraphRead},
		{method: "GET", path: "/api/v1/graph/reachable/{id}", opID: "graphReachable", summary: "Nodes reachable from a node (reachability query)", handler: a.graphReachable, pathParams: []string{"id"}, successCode: "200", perm: authz.GraphRead},
		{method: "GET", path: "/api/v1/graph/blast-radius/{id}", opID: "graphBlastRadius", summary: "Blast radius of compromising a node", handler: a.graphBlastRadius, pathParams: []string{"id"}, successCode: "200", perm: authz.GraphRead},
		{method: "POST", path: "/api/v1/graph/query", opID: "graphQuery", summary: "Run a Cypher-style graph query", handler: a.graphQuery, successCode: "200", perm: authz.GraphRead},

		{method: "GET", path: "/api/v1/risk/credentials", opID: "listRiskScores", summary: "Rank credentials by composite risk score", handler: a.listRiskScores, successCode: "200", perm: authz.RiskRead},

		{method: "GET", path: "/api/v1/agents", opID: "listAgents", summary: "List in-network agents", handler: a.listAgents, resSchema: "AgentList", successCode: "200", perm: authz.AgentsRead},
		{method: "POST", path: "/api/v1/agents/enrollment-tokens", opID: "createEnrollmentToken", summary: "Mint a one-time agent bootstrap token", handler: a.createEnrollmentToken, resSchema: "EnrollmentToken", successCode: "201", mutation: true, perm: authz.AgentsWrite},

		// Served secrets/identity surface (GAP-006): the secret store (CRUD + rotation,
		// secretsdk/F64), one-time secret sharing (secretshare/F60), and the dynamic PKI
		// secret (pkisecret/F67). Each is auth-gated, tenant-scoped under RLS (AN-1),
		// idempotent (AN-5), and event-sourced (AN-2); values are never logged or
		// returned beyond their design (AN-8). The machine-login route (authmethod/F58)
		// is PUBLIC and registered separately in New (it authenticates a credential).
		{method: "POST", path: "/api/v1/secrets/store", opID: "createSecret", summary: "Create an application secret (sealed at rest)", handler: a.createSecret, reqSchema: "SecretRequest", resSchema: "SecretMeta", successCode: "201", mutation: true, perm: authz.SecretsWrite},
		{method: "GET", path: "/api/v1/secrets/store", opID: "listSecrets", summary: "List application secret names (no values)", handler: a.listSecrets, query: page, resSchema: "SecretMetaList", successCode: "200", perm: authz.SecretsRead},
		{method: "GET", path: "/api/v1/secrets/store/{name...}", opID: "getSecret", summary: "Read an application secret value", handler: a.getSecret, pathParams: []string{"name"}, resSchema: "SecretValue", successCode: "200", perm: authz.SecretsRead},
		{method: "PUT", path: "/api/v1/secrets/store/{name...}", opID: "rotateSecret", summary: "Rotate an application secret (new value, bumped version)", handler: a.rotateSecret, pathParams: []string{"name"}, reqSchema: "SecretRequest", resSchema: "SecretMeta", successCode: "200", mutation: true, perm: authz.SecretsWrite},
		{method: "DELETE", path: "/api/v1/secrets/store/{name...}", opID: "deleteSecret", summary: "Delete an application secret", handler: a.deleteSecret, pathParams: []string{"name"}, successCode: "204", mutation: true, perm: authz.SecretsWrite},

		{method: "POST", path: "/api/v1/secrets/shares", opID: "createShare", summary: "Create a one-time secret share (returns a bearer token)", handler: a.createShare, reqSchema: "ShareRequest", resSchema: "ShareToken", successCode: "201", mutation: true, perm: authz.SecretsWrite},
		{method: "POST", path: "/api/v1/secrets/shares/redeem", opID: "redeemShare", summary: "Redeem a one-time secret share exactly once", handler: a.redeemShare, reqSchema: "ShareRedeemRequest", resSchema: "ShareValue", successCode: "200", mutation: true, perm: authz.SecretsRead},

		{method: "POST", path: "/api/v1/secrets/pki", opID: "issuePKISecret", summary: "Issue a dynamic PKI secret (short-lived cert + key)", handler: a.issuePKISecret, reqSchema: "PKISecretRequest", resSchema: "PKISecret", successCode: "201", mutation: true, perm: authz.SecretsWrite},

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
//
// TENANT-003 (fail closed): once a principal is present in the context, ITS tenant
// is authoritative and we never fall back to the client-supplied X-Tenant-ID
// header. A principal whose tenant is empty therefore yields (",", false) — a hard
// "no tenant", not a silent header fallback that an authenticated caller could use
// to operate in another tenant. The header path is reachable only when there is
// genuinely no principal (a truly public route).
func (a *API) tenant(r *http.Request) (string, bool) {
	if p, ok := r.Context().Value(principalCtxKey).(authz.Principal); ok {
		// An authenticated principal is bound to its own tenant. Do not consult the
		// header — an empty principal tenant fails closed instead of falling back.
		return p.TenantID, p.TenantID != ""
	}
	t, err := a.tenantFn(r)
	return t, err == nil && t != ""
}

// resolvePrincipal is the default, authenticated resolver: an Authorization:
// Bearer trustctl API token authenticates by its hash (carrying its own tenant
// and scopes), or a verified OIDC session cookie authenticates a browser user
// (carrying their tenant and roles). A request with neither is unauthenticated.
// It NEVER trusts client-supplied identity headers — that path is test-only
// (WithInsecureHeaderResolver) and is not linked into the production binary.
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
	if a.auth != nil {
		if sess, ok := a.sessionFrom(r); ok {
			return a.sessionPrincipal(sess), nil
		}
	}
	return authz.Principal{}, errors.New("api: unauthenticated")
}

// sessionPrincipal builds the RBAC principal for a verified OIDC session: the
// session's role names resolve (against the role registry) to grants held
// tenant-wide within the session's tenant. This is what makes a browser login
// authorize API calls, not just /auth/me.
func (a *API) sessionPrincipal(sess auth.Session) authz.Principal {
	grants := make([]authz.Grant, 0, len(sess.Roles))
	for _, name := range sess.Roles {
		if role, ok := a.roles.Role(name); ok {
			grants = append(grants, authz.Grant{Role: role, Scope: authz.Scope{TenantID: sess.TenantID}})
		}
	}
	return authz.Principal{TenantID: sess.TenantID, Subject: sess.Subject, Grants: grants}
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
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
		// CSRF defense for the cookie-session path (SEC-007): a session-authenticated
		// mutating request must carry a matching double-submit token. enforceCSRF is a
		// no-op for bearer-token callers (CSRF-immune), safe methods, and non-session
		// requests, so it only constrains the browser-cookie path; it writes 403 and
		// returns false when the token is missing/mismatched.
		if !a.enforceCSRF(w, r) {
			return
		}
		target := authz.Scope{TenantID: principal.TenantID, Project: r.Header.Get("X-Project")}
		if !principal.Can(perm, target) {
			a.writeProblem(w, problem.New(http.StatusForbidden, "forbidden: requires "+string(perm)))
			return
		}
		// Shed load per tenant (R2.3): an authenticated-but-over-budget caller is
		// rejected with 429 + Retry-After so one noisy tenant cannot exhaust the
		// control plane. Checked after authz so denials don't consume quota.
		if a.rateLimiter != nil {
			allowed, retryAfter, err := a.rateLimiter.Allow(r.Context(), principal.TenantID)
			if err != nil {
				a.writeError(w, err)
				return
			}
			if !allowed {
				if retryAfter > 0 {
					w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
				}
				a.writeProblem(w, problem.New(http.StatusTooManyRequests, "rate limit exceeded for this tenant"))
				return
			}
		}
		// Attribute every event this request appends to the authenticated caller
		// and the roles it acted under (R2.1) — the audit trail's who/under-what.
		ctx := context.WithValue(r.Context(), principalCtxKey, principal)
		ctx = events.ContextWithActor(ctx, events.Actor{Subject: principal.Subject, Roles: principalRoles(principal)})
		h(w, r.WithContext(ctx))
	}
}

// principalRoles returns the distinct role names a principal holds, for audit
// attribution (the "under what authorization").
func principalRoles(p authz.Principal) []string {
	seen := map[string]bool{}
	var roles []string
	for _, g := range p.Grants {
		if g.Role.Name != "" && !seen[g.Role.Name] {
			seen[g.Role.Name] = true
			roles = append(roles, g.Role.Name)
		}
	}
	return roles
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
	limit, err = pageLimit(r)
	if err != nil {
		return 0, "", err
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

// pageLimit parses just the page-size query parameter (1-100, default 20). It is
// shared by handlers that decode their own keyset cursor (e.g. the certificate
// inventory's composite expiry cursor, SPINE-006).
func pageLimit(r *http.Request) (int, error) {
	limit := 20
	if s := r.URL.Query().Get("limit"); s != "" {
		n, e := strconv.Atoi(s)
		if e != nil || n < 1 || n > 100 {
			return 0, errors.New("limit must be an integer between 1 and 100")
		}
		limit = n
	}
	return limit, nil
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
