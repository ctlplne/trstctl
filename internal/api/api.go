package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/breakglass"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/policy"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

const (
	specPath                 = "/api/v1/openapi.json"
	defaultRESTJSONBodyLimit = 1 << 20 // 1 MiB caps the shared authenticated REST JSON surface.
)

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
	store                   *store.Store
	log                     *events.Log
	idem                    *orchestrator.Idempotency
	orch                    *orchestrator.Orchestrator
	tenantFn                func(*http.Request) (string, error)
	roles                   *authz.Registry
	principal               func(*http.Request) (authz.Principal, error)
	audit                   *audit.Service
	auth                    *AuthConfig
	oidcPreLogin            *oidcPreLoginStore
	scim                    *SCIMConfig
	scimTokens              map[string]scimToken
	agentTokens             BootstrapTokenIssuer
	agentEnroller           BootstrapEnroller
	agentEnrollmentObserver func(result string)
	rateLimiter             RateLimiter
	gate                    MutationGate
	abac                    ABACDenyEvaluator
	abacEnvironment         map[string]string
	abacNow                 func() time.Time
	approvals               ApprovalRecorder
	breakglass              BreakglassReconciler
	breakglassIssuer        BreakglassIssuer
	breakglassAdmin         *breakglass.AdminService
	caHierarchy             CAHierarchyService
	externalCAs             ExternalCAService
	attestedIssuer          AttestedIssuerService
	sshWorkflow             SSHWorkflowService
	broker                  BrokerService
	ephemeral               EphemeralIssuerService
	pam                     PAMService
	managedKeys             ManagedKeyService // served BYOK/HSM key lifecycle (CRYPTO-005); nil = not enabled
	transit                 TransitService    // served transit/EaaS key operations (KMS-01); nil = not enabled
	codeSigning             CodeSigningService
	ctSubmission            CTSubmissionService
	secrets                 *secretsService // served secrets/identity surface (GAP-006); nil = not enabled
	ai                      *aiSurface      // served AI/RCA/NL-query/MCP surface (SURFACE-003); nil = not enabled
	cbom                    CBOMService     // served CBOM scanner + PQC migration inventory (PQC-05)
	pqcMigration            PQCMigrationService
	complianceEvidence      ComplianceEvidenceService
	license                 *license.Manager
	remediation             bool
	notificationChannels    []string
	notificationOutbox      *orchestrator.Outbox
	outboxCircuits          func() []orchestrator.CircuitSnapshot
	privacyRetentionPolicy  privacy.RetentionPolicy
	privacyRetentionSource  privacy.RetentionPolicySource
	// featureObserver records a per-feature operation signal (COVER-009). It receives
	// only closed-set, non-sensitive labels (feature, action, outcome) and the
	// duration — never tenant or credential data. nil disables per-feature telemetry.
	featureObserver func(feature, action, outcome string, seconds float64)
	mux             *http.ServeMux
	spec            *Document
}

// Option configures an API.
type Option func(*config)

type config struct {
	customRoles []authz.Role
	eventLog    *events.Log
	principalFn func(*http.Request) (authz.Principal, error)
	// principalFromReg is a resolver factory the test-only header resolver uses.
	// It is built against the API's role registry (so custom roles work) and the
	// real authenticated resolver (so test servers still accept bearer tokens and
	// sessions). It is referenced only from WithInsecureHeaderResolver, so it is
	// not linked into the production build. See WithInsecureHeaderResolver.
	principalFromReg        func(reg *authz.Registry, fallback func(*http.Request) (authz.Principal, error)) func(*http.Request) (authz.Principal, error)
	audit                   *audit.Service
	auth                    *AuthConfig
	scim                    *SCIMConfig
	agentTokens             BootstrapTokenIssuer
	agentEnroller           BootstrapEnroller
	agentEnrollmentObserver func(result string)
	rateLimiter             RateLimiter
	gate                    MutationGate
	abac                    ABACDenyEvaluator
	abacEnvironment         map[string]string
	abacNow                 func() time.Time
	approvals               ApprovalRecorder
	breakglass              BreakglassReconciler
	breakglassIssuer        BreakglassIssuer
	breakglassAdmin         *breakglass.AdminService
	caHierarchy             CAHierarchyService
	externalCAs             ExternalCAService
	attestedIssuer          AttestedIssuerService
	sshWorkflow             SSHWorkflowService
	broker                  BrokerService
	ephemeral               EphemeralIssuerService
	pam                     PAMService
	managedKeys             ManagedKeyService
	transit                 TransitService
	codeSigning             CodeSigningService
	ctSubmission            CTSubmissionService
	secrets                 *secretsService
	ai                      *aiSurface
	cbom                    CBOMService
	pqcMigration            PQCMigrationService
	complianceEvidence      ComplianceEvidenceService
	license                 *license.Manager
	remediation             bool
	notificationChannels    []string
	notificationOutbox      *orchestrator.Outbox
	outboxCircuits          func() []orchestrator.CircuitSnapshot
	privacyRetentionPolicy  privacy.RetentionPolicy
	privacyRetentionSource  privacy.RetentionPolicySource
	featureObserver         func(feature, action, outcome string, seconds float64)
}

// WithAudit wires the audit-log service that backs the /api/v1/audit endpoints.
func WithAudit(svc *audit.Service) Option {
	return func(c *config) { c.audit = svc }
}

// WithRoles registers custom (tenant-defined) roles alongside the built-ins.
func WithRoles(roles ...authz.Role) Option {
	return func(c *config) { c.customRoles = append(c.customRoles, roles...) }
}

// WithEventLog wires the source-of-truth event log for REST mutations that own a
// small projection directly (for example notification read receipts). Mutations
// still run through the idempotency wrapper; this option only gives them the
// append-only log required by AN-2.
func WithEventLog(log *events.Log) Option {
	return func(c *config) { c.eventLog = log }
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

// WithAgentEnrollmentObserver records aggregate bootstrap-enrollment outcomes for
// fleet rollout observability. The observer receives a low-cardinality result
// label ("success" or "failed") and must not depend on per-agent identifiers.
func WithAgentEnrollmentObserver(fn func(result string)) Option {
	return func(c *config) { c.agentEnrollmentObserver = fn }
}

// WithOutboxCircuitStatus wires the operator-visible outbox destination circuit
// snapshot provider. The route filters snapshots to the authenticated tenant.
func WithOutboxCircuitStatus(fn func() []orchestrator.CircuitSnapshot) Option {
	return func(c *config) { c.outboxCircuits = fn }
}

// WithFeatureObserver wires per-feature telemetry (COVER-009). The hook is called
// once per served high-risk feature operation (issuance, revocation, deployment,
// discovery, certificate ingest) with closed-set, non-sensitive labels — the feature
// and action names, an outcome of "success" or "error", and the operation duration in
// seconds. It must never receive tenant or credential data (AN-1, AN-8); the server
// passes observ.FeatureMetrics.Hook(), which records on the metrics registry.
func WithFeatureObserver(fn func(feature, action, outcome string, seconds float64)) Option {
	return func(c *config) { c.featureObserver = fn }
}

// WithLicense wires the offline license manager that backs GET /v1/editions.
// nil keeps the default Community posture.
func WithLicense(m *license.Manager) Option {
	return func(c *config) { c.license = m }
}

// WithRemediation mounts the Enterprise remediation HTTP surface. Without it the
// route registry still describes the full licensed API contract, but the runtime
// mux returns 404 for incident/PQC remediation paths so Community cannot probe a
// dormant mutating surface.
func WithRemediation() Option {
	return func(c *config) { c.remediation = true }
}

// WithNotificationChannels wires the read-only channel catalog with the channel
// names registered in the running process. It does not expose secrets or make
// tenant-side authoring claims.
func WithNotificationChannels(names ...string) Option {
	return func(c *config) { c.notificationChannels = append([]string(nil), names...) }
}

// WithNotificationOutbox wires the served outbox used to queue operator-requested
// notification channel tests. Delivery still happens only in the outbox worker.
func WithNotificationOutbox(outbox *orchestrator.Outbox) Option {
	return func(c *config) { c.notificationOutbox = outbox }
}

// observeFeature emits one per-feature telemetry signal (COVER-009) if an observer is
// wired. feature and action MUST be closed-set constants (never tenant/credential
// strings); err selects the success/error outcome. start times the operation. It is a
// no-op when no observer is configured. The outcome strings match observ.Outcome*; the
// API depends only on the func value (not the observ package) so the layering stays
// the same as the other API observer hooks.
func (a *API) observeFeature(feature, action string, start time.Time, err error) {
	if a.featureObserver == nil {
		return
	}
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	a.featureObserver(feature, action, outcome, time.Since(start).Seconds())
}

// transitionFeatureAction maps a lifecycle target state to the (feature, action)
// telemetry labels for that served transition (COVER-009). The labels are a closed
// set drawn from the feature catalog; an unknown target maps to the lifecycle feature
// with the raw state as the action only if it is one of the known states, else it
// reports no signal (ok=false) so a future state cannot silently widen the label set.
func transitionFeatureAction(to orchestrator.State) (feature, action string, ok bool) {
	switch to {
	case orchestrator.StateIssued:
		return "issuance", "issue", true
	case orchestrator.StateDeployed:
		return "deployment", "deploy", true
	case orchestrator.StateRenewing:
		return "deployment", "renew", true
	case orchestrator.StateRevoked:
		return "revocation", "revoke", true
	case orchestrator.StateRetired:
		return "revocation", "retire", true
	default:
		return "", "", false
	}
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

// WithPrivacyRetentionPolicy sets the policy used by the served manual privacy
// retention endpoint. The background worker receives its copy through server.Deps.
func WithPrivacyRetentionPolicy(policy privacy.RetentionPolicy) Option {
	return func(c *config) { c.privacyRetentionPolicy = policy.WithDefaults() }
}

// WithPrivacyRetentionPolicySource wires the optional licensed governance policy
// source consulted by the core retention mechanism. Nil keeps core defaults.
func WithPrivacyRetentionPolicySource(source privacy.RetentionPolicySource) Option {
	return func(c *config) { c.privacyRetentionSource = source }
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

// WithABACDenyOverlay wires the deny-only attribute overlay onto every guarded API
// route. RBAC must allow first; ABAC can only veto with request, actor, time, and
// deployment environment attributes. Rich identity resource tags are added by the
// lifecycle MutationGate for issue/deploy/revoke transitions.
func WithABACDenyOverlay(eval ABACDenyEvaluator, environment map[string]string, now func() time.Time) Option {
	return func(c *config) {
		c.abac = eval
		c.abacEnvironment = copyStringMap(environment)
		c.abacNow = now
	}
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
	policy := cfg.privacyRetentionPolicy
	if policy == (privacy.RetentionPolicy{}) {
		policy = privacy.DefaultRetentionPolicy()
	}
	a := &API{
		store:                   st,
		log:                     cfg.eventLog,
		idem:                    idem,
		orch:                    orch,
		tenantFn:                tenantFromHeader,
		roles:                   reg,
		audit:                   cfg.audit,
		auth:                    cfg.auth,
		scim:                    cfg.scim,
		scimTokens:              normalizeSCIM(cfg.scim),
		agentTokens:             cfg.agentTokens,
		agentEnroller:           cfg.agentEnroller,
		agentEnrollmentObserver: cfg.agentEnrollmentObserver,
		rateLimiter:             cfg.rateLimiter,
		gate:                    cfg.gate,
		abac:                    cfg.abac,
		abacEnvironment:         copyStringMap(cfg.abacEnvironment),
		abacNow:                 cfg.abacNow,
		approvals:               cfg.approvals,
		breakglass:              cfg.breakglass,
		breakglassIssuer:        cfg.breakglassIssuer,
		breakglassAdmin:         cfg.breakglassAdmin,
		caHierarchy:             cfg.caHierarchy,
		externalCAs:             cfg.externalCAs,
		attestedIssuer:          cfg.attestedIssuer,
		sshWorkflow:             cfg.sshWorkflow,
		broker:                  cfg.broker,
		ephemeral:               cfg.ephemeral,
		pam:                     cfg.pam,
		managedKeys:             cfg.managedKeys,
		transit:                 cfg.transit,
		codeSigning:             cfg.codeSigning,
		ctSubmission:            cfg.ctSubmission,
		secrets:                 cfg.secrets,
		ai:                      cfg.ai,
		cbom:                    cfg.cbom,
		pqcMigration:            cfg.pqcMigration,
		complianceEvidence:      cfg.complianceEvidence,
		license:                 cfg.license,
		remediation:             cfg.remediation,
		notificationChannels:    append([]string(nil), cfg.notificationChannels...),
		notificationOutbox:      cfg.notificationOutbox,
		outboxCircuits:          cfg.outboxCircuits,
		featureObserver:         cfg.featureObserver,
		privacyRetentionPolicy:  policy.WithDefaults(),
		privacyRetentionSource:  cfg.privacyRetentionSource,
	}
	if a.auth != nil {
		a.oidcPreLogin = newOIDCPreLoginStore(a.auth.PreLoginTTL)
	}
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
		if !a.routeEnabled(r) {
			continue
		}
		mux.HandleFunc(r.method+" "+r.path, a.guard(r.perm, r.scope, r.handler))
	}
	// Compatibility alias for the probectl editions surface. The canonical,
	// generated trstctl REST path is /api/v1/editions; this exact public read
	// route serves the same handler so operators can probe the shorter posture URL
	// without creating a second OpenAPI/client operation.
	mux.HandleFunc("GET /v1/editions", a.getEditions)
	a.mountVaultCompat(mux)
	// The browser SSO login + session bridge for the web UI. These routes are
	// registered outside the route registry so they stay out of the CLI/OpenAPI
	// surface.
	if a.auth != nil {
		if a.auth.OIDCEnabled || a.auth.Exchange != nil || a.auth.VerifyIDToken != nil {
			mux.HandleFunc("GET /auth/login", a.authLogin)
			mux.HandleFunc("GET /auth/callback", a.authCallback)
		}
		if a.auth.VerifyOIDCLogoutToken != nil {
			mux.HandleFunc("POST /auth/oidc/back-channel-logout", a.authOIDCBackChannelLogout)
		}
		if a.auth.SAMLEnabled || a.auth.VerifySAMLResponse != nil {
			mux.HandleFunc("GET /auth/saml/login", a.authSAMLLogin)
			mux.HandleFunc("POST /auth/saml/acs", a.authSAMLACS)
			mux.HandleFunc("GET /auth/saml/metadata", a.authSAMLMetadata)
		}
		if a.auth.LDAPEnabled || a.auth.VerifyLDAPLogin != nil {
			mux.HandleFunc("POST /auth/ldap/login", a.authLDAPLogin)
		}
		mux.HandleFunc("GET /auth/me", a.authMe)
		mux.HandleFunc("POST /auth/logout", a.authLogout)
	}
	if a.breakglassAdmin != nil && a.breakglassAdmin.Enabled() {
		mux.HandleFunc("POST /auth/breakglass/login", a.authBreakglassAdminLogin)
	}
	// Agent bootstrap enrollment (S5.1/F15). The one-time token authenticates the
	// request, so this route carries no RBAC permission and stays out of the
	// /api, CLI, and OpenAPI surfaces — the same treatment as the OIDC bridge.
	if a.agentEnroller != nil {
		mux.HandleFunc("POST /enroll/bootstrap", a.enrollBootstrap)
	}
	if len(a.scimTokens) > 0 {
		mux.HandleFunc("GET /scim/v2/ServiceProviderConfig", a.scimServiceProviderConfig)
		mux.HandleFunc("POST /scim/v2/Users", a.scimCreateUser)
		mux.HandleFunc("GET /scim/v2/Users", a.scimListUsers)
		mux.HandleFunc("GET /scim/v2/Users/{id}", a.scimGetUser)
		mux.HandleFunc("PUT /scim/v2/Users/{id}", a.scimPutUser)
		mux.HandleFunc("PATCH /scim/v2/Users/{id}", a.scimPatchUser)
		mux.HandleFunc("DELETE /scim/v2/Users/{id}", a.scimDeleteUser)
		mux.HandleFunc("POST /scim/v2/Groups", a.scimCreateGroup)
		mux.HandleFunc("GET /scim/v2/Groups", a.scimListGroups)
		mux.HandleFunc("GET /scim/v2/Groups/{id}", a.scimGetGroup)
		mux.HandleFunc("PATCH /scim/v2/Groups/{id}", a.scimPatchGroup)
		mux.HandleFunc("DELETE /scim/v2/Groups/{id}", a.scimDeleteGroup)
	}
	mux.HandleFunc("/", a.notFound)
	a.mux = mux
	a.spec = buildSpec(a.routes())
	return a
}

// ServeHTTP implements http.Handler.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.mux.ServeHTTP(w, r) }

func (a *API) routeEnabled(r route) bool {
	switch r.opID {
	case "executeIncident", "listIncidentExecutions", "getIncidentExecution",
		"startFleetReissuance", "listFleetReissuanceRuns", "getFleetReissuanceRun",
		"pauseFleetReissuance", "resumeFleetReissuance", "rollbackFleetReissuance", "exportFleetReissuanceEvidence",
		"listRemediationPlaybooks", "runRemediationPlaybook", "listRemediationPlaybookRuns", "getRemediationPlaybookRun",
		"listOwnerRemediationActions", "acceptOwnerRemediationAction",
		"dispatchResponseIntegrations",
		"startPQCMigration", "rollbackPQCMigration":
		return a.remediation
	case "generateManagedKey", "rotateManagedKey", "revokeManagedKey", "zeroizeManagedKey":
		return a.managedKeys != nil
	case "getComplianceEvidencePack":
		return a.complianceEvidence != nil
	default:
		return true
	}
}

// Route is a served (method, path) pair, exposed so documentation tooling and
// tests can confirm the spec covers every route and that each route has an
// authorization contract.
type Route struct {
	Method            string
	Path              string
	OperationID       string
	Permission        authz.Permission
	PublicRationale   string
	Mutation          bool
	SensitiveResponse bool
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
		out = append(out, Route{
			Method:            r.method,
			Path:              openapiPath(r.path),
			OperationID:       r.opID,
			Permission:        r.perm,
			PublicRationale:   publicRationaleForRoute(r),
			Mutation:          r.mutation,
			SensitiveResponse: r.sensitiveResponse,
		})
	}
	return out
}

// openapiPath normalizes a route path to its OpenAPI-template form by reducing a
// trailing-wildcard segment ("{name...}") to "{name}". It is the single place that
// mapping lives, shared by Routes and buildSpec.
func openapiPath(p string) string { return strings.ReplaceAll(p, "...}", "}") }

func publicRationaleForRoute(r route) string {
	if r.perm != "" {
		return ""
	}
	switch r.opID {
	case "machineLogin":
		return "public credential exchange: the presented machine credential authenticates the workload and yields a tenant-scoped session."
	case "getOpenAPISpec":
		return "public static API contract: the document contains no tenant data or credential material."
	case "getEditions":
		return "public edition posture: the response contains only global license state, feature-table rows, and crypto posture; it carries no tenant data or credential material."
	default:
		return ""
	}
}

// param is an OpenAPI query parameter descriptor.
type param struct {
	name   string
	typ    string
	format string
	desc   string
}

func pathUUID(name string) param {
	return param{name: name, typ: "string", format: "uuid"}
}

func pathString(name, desc string) param {
	return param{name: name, typ: "string", desc: desc}
}

func pathInteger(name, desc string) param {
	return param{name: name, typ: "integer", desc: desc}
}

// route binds an HTTP method+path to a handler and carries the metadata used to
// generate the OpenAPI document and to enforce RBAC.
type route struct {
	method            string
	path              string
	opID              string
	summary           string
	handler           http.HandlerFunc
	pathParams        []param
	query             []param
	reqSchema         string
	resSchema         string
	successCode       string
	mutation          bool
	sensitiveResponse bool
	perm              authz.Permission // required permission; "" means public
	scope             routeScope
}

type routeScope func(*http.Request) (authz.Scope, error)

func scopeIssuerPath(name string) routeScope {
	return func(r *http.Request) (authz.Scope, error) {
		return authz.Scope{Issuer: strings.TrimSpace(r.PathValue(name))}, nil
	}
}

func scopeProfilePath(name string) routeScope {
	return func(r *http.Request) (authz.Scope, error) {
		return authz.Scope{Profile: strings.TrimSpace(r.PathValue(name))}, nil
	}
}

func scopeProfileJSON(field string) routeScope {
	return func(r *http.Request) (authz.Scope, error) {
		value, err := jsonBodyStringField(r, field)
		if err != nil {
			return authz.Scope{}, err
		}
		return authz.Scope{Profile: value}, nil
	}
}

func combineRouteScopes(scopes ...routeScope) routeScope {
	return func(r *http.Request) (authz.Scope, error) {
		var out authz.Scope
		for _, scope := range scopes {
			if scope == nil {
				continue
			}
			next, err := scope(r)
			if err != nil {
				return authz.Scope{}, err
			}
			if err := mergeRouteScope(&out, next); err != nil {
				return authz.Scope{}, err
			}
		}
		return out, nil
	}
}

func mergeRouteScope(dst *authz.Scope, next authz.Scope) error {
	if err := mergeScopeDimension(&dst.TenantID, next.TenantID, "tenant"); err != nil {
		return err
	}
	if err := mergeScopeDimension(&dst.Project, next.Project, "project"); err != nil {
		return err
	}
	if err := mergeScopeDimension(&dst.Profile, next.Profile, "profile"); err != nil {
		return err
	}
	if err := mergeScopeDimension(&dst.Issuer, next.Issuer, "issuer"); err != nil {
		return err
	}
	return nil
}

func mergeScopeDimension(dst *string, next, label string) error {
	next = strings.TrimSpace(next)
	if next == "" {
		return nil
	}
	if *dst != "" && *dst != next {
		return errStatus(http.StatusBadRequest, "conflicting "+label+" scope")
	}
	*dst = next
	return nil
}

func jsonBodyStringField(r *http.Request, field string) (string, error) {
	if r.Body == nil {
		return "", nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, defaultRESTJSONBodyLimit+1))
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return "", errStatus(http.StatusBadRequest, "invalid JSON body")
	}
	if len(body) == 0 {
		return "", nil
	}
	if len(body) > defaultRESTJSONBodyLimit {
		return "", errStatus(http.StatusRequestEntityTooLarge, "request body too large")
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", errStatus(http.StatusBadRequest, "invalid JSON body")
	}
	raw, ok := payload[field]
	if !ok || len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", errStatus(http.StatusBadRequest, field+" must be a string")
	}
	return strings.TrimSpace(value), nil
}

func (a *API) routes() []route {
	idPath := []param{pathUUID("id")}
	graphNodePath := []param{pathString("id", "credential graph node id")}
	profileVersionPath := []param{
		pathString("name", "certificate profile name"),
		pathInteger("version", "positive certificate profile version"),
	}
	memberSubjectPath := []param{pathString("subject", "tenant member subject")}
	nhiReviewItemPath := []param{pathUUID("id"), pathUUID("item_id")}
	mcpToolPath := []param{pathString("tool", "MCP tool name")}
	notificationIDPath := []param{pathInteger("id", "notification outbox id")}
	secretNamePath := []param{pathString("name", "hierarchical secret name")}
	dynamicLeaseIDPath := []param{pathString("lease_id", "dynamic secret lease id")}
	pqcMigrationRunPath := []param{pathString("run_id", "PQC migration run id")}
	playbookIDPath := []param{pathString("id", "remediation playbook id")}
	complianceFrameworkPath := []param{pathString("framework", "compliance framework path value, for example soc2, nist-800-53, fedramp, cmmc-2.0, eidas, or nis2")}
	caCeremonyPath := []param{pathUUID("id")}
	caAuthorityPath := []param{pathUUID("id")}
	dns01ProviderConfigPath := []param{pathUUID("id")}
	externalCAPath := []param{pathString("id", "configured external CA registry id")}
	notificationChannelPath := []param{pathString("id", "notification channel id")}
	notificationRoutingPolicyPath := []param{pathUUID("id")}
	ephemeralRequestPath := []param{pathString("id", "ephemeral JIT request id")}
	page := []param{
		{name: "limit", typ: "integer", desc: "maximum items per page (1-100, default 20)"},
		{name: "cursor", typ: "string", desc: "opaque pagination cursor from a prior page"},
	}
	notificationQuery := []param{
		{name: "limit", typ: "integer", desc: "maximum items per page (1-100, default 20)"},
		{name: "cursor", typ: "string", desc: "opaque notification id cursor from a prior page"},
		{name: "status", typ: "string", desc: "filter by pending, sent, dead, or read"},
	}
	certQuery := []param{
		{name: "limit", typ: "integer", desc: "maximum items per page (1-100, default 20)"},
		{name: "cursor", typ: "string", desc: "opaque pagination cursor from a prior page"},
		{name: "expiring_before", typ: "string", desc: "RFC3339; return only certificates expiring before this time"},
	}
	discoveryFindingQuery := []param{
		{name: "limit", typ: "integer", desc: "maximum items per page (1-100, default 20)"},
		{name: "cursor", typ: "string", desc: "opaque pagination cursor from a prior page"},
		{name: "run_id", typ: "string", format: "uuid", desc: "return only findings from this discovery run"},
	}
	identityScopedPage := []param{
		{name: "limit", typ: "integer", desc: "maximum items per page (1-100, default 20)"},
		{name: "cursor", typ: "string", desc: "opaque pagination cursor from a prior page"},
		{name: "identity_id", typ: "string", format: "uuid", desc: "return only records for this identity"},
	}
	incidentScopedPage := []param{
		{name: "limit", typ: "integer", desc: "maximum items per page (1-100, default 20)"},
		{name: "cursor", typ: "string", desc: "opaque pagination cursor from a prior page"},
		{name: "identity_id", typ: "string", format: "uuid", desc: "return only executions for this compromised identity"},
	}
	issuerScopedPage := []param{
		{name: "limit", typ: "integer", desc: "maximum items per page (1-100, default 20)"},
		{name: "cursor", typ: "string", desc: "opaque pagination cursor from a prior page"},
		{name: "issuer_id", typ: "string", format: "uuid", desc: "return only runs for this compromised issuer"},
	}
	playbookScopedPage := []param{
		{name: "limit", typ: "integer", desc: "maximum items per page (1-100, default 20)"},
		{name: "cursor", typ: "string", desc: "opaque pagination cursor from a prior page"},
		{name: "playbook_id", typ: "string", desc: "return only runs for this remediation playbook"},
	}
	auditQuery := []param{
		{name: "type", typ: "string", desc: "comma-separated event types to include"},
		{name: "feature_id", typ: "string", desc: "catalog feature id (e.g. F6); returns only events the feature's mutating actions emit"},
		{name: "action", typ: "string", desc: "catalog action (e.g. revoke); returns only events that action emits, optionally scoped by feature_id"},
		{name: "since", typ: "string", desc: "RFC3339 inclusive lower time bound"},
		{name: "until", typ: "string", desc: "RFC3339 inclusive upper time bound"},
		{name: "as_of", typ: "integer", desc: "point-in-time: only tenant-local audit events with sequence <= this"},
		{name: "q", typ: "string", desc: "substring match on event type or data"},
		{name: "limit", typ: "integer", desc: "maximum records to return"},
	}
	memberQuery := []param{
		{name: "limit", typ: "integer", desc: "maximum items per page (1-100, default 20)"},
		{name: "cursor", typ: "string", desc: "opaque subject cursor from a prior page"},
		{name: "include_offboarded", typ: "boolean", desc: "include offboarded member tombstones"},
	}
	apiTokenQuery := []param{
		{name: "limit", typ: "integer", desc: "maximum items per page (1-100, default 20)"},
		{name: "cursor", typ: "string", desc: "opaque token cursor from a prior page"},
		{name: "subject", typ: "string", desc: "return tokens for one subject"},
		{name: "include_revoked", typ: "boolean", desc: "include revoked API tokens"},
	}
	privacyErasureQuery := []param{
		{name: "limit", typ: "integer", desc: "maximum items per page (1-100, default 20)"},
		{name: "cursor", typ: "string", desc: "opaque subject-erasure cursor from a prior page"},
	}
	privacyRetentionQuery := []param{
		{name: "limit", typ: "integer", desc: "maximum items per page (1-100, default 20)"},
		{name: "cursor", typ: "string", desc: "opaque retention-run cursor from a prior page"},
	}
	return []route{
		{method: "GET", path: "/api/v1/editions", opID: "getEditions", summary: "Edition and license posture", handler: a.getEditions, resSchema: "EditionsInfo", successCode: "200"},
		{method: "GET", path: "/api/v1/support/enterprise", opID: "getEnterpriseSupportStatus", summary: "Enterprise support, SLA, and services posture", handler: a.getEnterpriseSupportStatus, resSchema: "EnterpriseSupportStatus", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/managed-offering/status", opID: "getManagedOfferingStatus", summary: "Managed offering/provider-plane posture", handler: a.getManagedOfferingStatus, resSchema: "ManagedOfferingStatus", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/scale/orchestration", opID: "getScaleOrchestration", summary: "High-volume orchestration posture for 100k-1M+ credentials", handler: a.getScaleOrchestration, resSchema: "ScaleOrchestrationPlan", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/scale/ha-issuance", opID: "getActiveActiveIssuance", summary: "Multi-region HA issuance posture", handler: a.getActiveActiveIssuance, resSchema: "ActiveActiveIssuancePlan", successCode: "200", perm: authz.AccessRead},
		// Provider-plane tenant creation is a tenant-scoped system operation: the
		// provider tenant is authorized by the bearer principal, while the command
		// emits tenant.registered for the hosted tenant so PostgreSQL RLS creates a
		// separate boundary from the first projected row.
		{method: "POST", path: "/api/v1/managed-offering/tenants", opID: "provisionManagedTenant", summary: "Provision a hosted tenant in the managed offering", handler: a.provisionManagedTenant, reqSchema: "ManagedTenantProvisionRequest", resSchema: "ManagedTenant", successCode: "201", mutation: true, perm: authz.AccessWrite},

		{method: "POST", path: "/api/v1/owners", opID: "createOwner", summary: "Create an owner", handler: a.createOwner, reqSchema: "OwnerRequest", resSchema: "Owner", successCode: "201", mutation: true, perm: authz.OwnersWrite},
		{method: "GET", path: "/api/v1/owners", opID: "listOwners", summary: "List owners", handler: a.listOwners, query: page, resSchema: "OwnerList", successCode: "200", perm: authz.OwnersRead},
		{method: "GET", path: "/api/v1/owners/{id}", opID: "getOwner", summary: "Get an owner", handler: a.getOwner, pathParams: idPath, resSchema: "Owner", successCode: "200", perm: authz.OwnersRead},
		{method: "PUT", path: "/api/v1/owners/{id}", opID: "updateOwner", summary: "Replace an owner", handler: a.updateOwner, pathParams: idPath, reqSchema: "OwnerRequest", resSchema: "Owner", successCode: "200", mutation: true, perm: authz.OwnersWrite},
		{method: "DELETE", path: "/api/v1/owners/{id}", opID: "deleteOwner", summary: "Delete an owner", handler: a.deleteOwner, pathParams: idPath, successCode: "204", mutation: true, perm: authz.OwnersWrite},

		{method: "POST", path: "/api/v1/issuers", opID: "createIssuer", summary: "Create an issuer", handler: a.createIssuer, reqSchema: "IssuerRequest", resSchema: "Issuer", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "GET", path: "/api/v1/issuers", opID: "listIssuers", summary: "List issuers", handler: a.listIssuers, query: page, resSchema: "IssuerList", successCode: "200", perm: authz.IssuersRead},
		{method: "GET", path: "/api/v1/issuers/{id}", opID: "getIssuer", summary: "Get an issuer", handler: a.getIssuer, pathParams: idPath, resSchema: "Issuer", successCode: "200", perm: authz.IssuersRead, scope: scopeIssuerPath("id")},
		{method: "POST", path: "/api/v1/ca/ceremonies", opID: "createCACeremony", summary: "Start an m-of-n CA key ceremony", handler: a.createCACeremony, reqSchema: "CACeremonyStartRequest", resSchema: "CAKeyCeremony", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "GET", path: "/api/v1/ca/ceremonies/{id}", opID: "getCACeremony", summary: "Get a CA key ceremony", handler: a.getCACeremony, pathParams: caCeremonyPath, resSchema: "CAKeyCeremony", successCode: "200", perm: authz.IssuersRead},
		{method: "POST", path: "/api/v1/ca/ceremonies/{id}/approvals", opID: "approveCACeremony", summary: "Approve a CA key ceremony", handler: a.approveCACeremony, pathParams: caCeremonyPath, resSchema: "CAKeyCeremony", successCode: "200", mutation: true, perm: authz.IssuersWrite},
		{method: "GET", path: "/api/v1/ca/discovery", opID: "listCADiscoveryInventory", summary: "List public and private CA discovery inventory", handler: a.listCADiscoveryInventory, resSchema: "CADiscoveryInventory", successCode: "200", perm: authz.IssuersRead},
		{method: "GET", path: "/api/v1/ca/authorities", opID: "listCAAuthorities", summary: "List served CA authorities", handler: a.listCAAuthorities, resSchema: "CAAuthorityList", successCode: "200", perm: authz.IssuersRead},
		{method: "POST", path: "/api/v1/ca/authorities/roots", opID: "createRootCA", summary: "Create a signer-backed root CA after ceremony quorum", handler: a.createRootCA, reqSchema: "CACreateRootRequest", resSchema: "CAAuthority", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "POST", path: "/api/v1/ca/authorities/offline-roots", opID: "importOfflineRootCA", summary: "Import an offline root CA certificate after ceremony quorum", handler: a.importOfflineRootCA, reqSchema: "CAImportOfflineRootRequest", resSchema: "CAAuthority", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "POST", path: "/api/v1/ca/authorities/imported", opID: "importExistingCA", summary: "Import an existing signer-backed CA certificate chain after ceremony quorum", handler: a.importExistingCA, reqSchema: "CAImportExistingRequest", resSchema: "CAAuthority", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "POST", path: "/api/v1/ca/authorities/intermediates", opID: "createIntermediateCA", summary: "Create a signer-backed intermediate CA after ceremony quorum", handler: a.createIntermediateCA, reqSchema: "CACreateIntermediateRequest", resSchema: "CAAuthority", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "POST", path: "/api/v1/ca/authorities/{id}/offline-intermediates/csr", opID: "createOfflineIntermediateCSR", summary: "Create a signer-backed intermediate CSR for an offline root", handler: a.createOfflineIntermediateCSR, pathParams: caAuthorityPath, reqSchema: "CACreateOfflineIntermediateCSRRequest", resSchema: "CAIntermediateCSR", successCode: "201", mutation: true, perm: authz.IssuersWrite, scope: scopeIssuerPath("id")},
		{method: "POST", path: "/api/v1/ca/authorities/{id}/offline-intermediates", opID: "importOfflineIntermediateCA", summary: "Import an offline-root-signed intermediate CA certificate", handler: a.importOfflineIntermediateCA, pathParams: caAuthorityPath, reqSchema: "CAImportOfflineIntermediateRequest", resSchema: "CAAuthority", successCode: "201", mutation: true, perm: authz.IssuersWrite, scope: scopeIssuerPath("id")},
		{method: "POST", path: "/api/v1/ca/authorities/{id}/intermediates/csr", opID: "issueIntermediateCAFromCSR", summary: "Sign an external intermediate CA CSR from a served CA authority after ceremony quorum", handler: a.issueHierarchyIntermediateCSR, pathParams: caAuthorityPath, reqSchema: "CAIssueIntermediateRequest", resSchema: "CAIssuedIntermediate", successCode: "201", mutation: true, perm: authz.IssuersWrite, scope: scopeIssuerPath("id")},
		{method: "POST", path: "/api/v1/ca/authorities/{id}/issue", opID: "issueHierarchyLeaf", summary: "Issue a leaf certificate from a served CA authority", handler: a.issueHierarchyLeaf, pathParams: caAuthorityPath, reqSchema: "CAIssueLeafRequest", resSchema: "CAIssuedLeaf", successCode: "201", mutation: true, perm: authz.CertsIssue, scope: scopeIssuerPath("id")},
		{method: "POST", path: "/api/v1/ca/authorities/{id}/rotate", opID: "rotateCAAuthority", summary: "Activate a signer-backed successor CA without changing the stable issue URL", handler: a.rotateCAAuthority, pathParams: caAuthorityPath, reqSchema: "CAAuthorityRotationRequest", resSchema: "CAAuthorityRotation", successCode: "200", mutation: true, perm: authz.IssuersWrite, scope: scopeIssuerPath("id")},
		{method: "POST", path: "/api/v1/ca/authorities/{id}/rekey", opID: "rekeyCAAuthority", summary: "Re-key a signer-backed CA authority after ceremony quorum", handler: a.rekeyCAAuthority, pathParams: caAuthorityPath, reqSchema: "CAAuthorityRekeyRequest", resSchema: "CAAuthorityRotation", successCode: "201", mutation: true, perm: authz.IssuersWrite, scope: scopeIssuerPath("id")},
		{method: "GET", path: "/api/v1/acme/dns-01/providers", opID: "listACMEDNS01Providers", summary: "List served ACME DNS-01 provider coverage", handler: a.listACMEDNS01Providers, resSchema: "ACMEDNS01ProviderCatalog", successCode: "200", perm: authz.IssuersRead},
		{method: "POST", path: "/api/v1/acme/dns-01/provider-configs", opID: "createACMEDNS01ProviderConfig", summary: "Create a served ACME DNS-01 provider config using secret references", handler: a.createACMEDNS01ProviderConfig, reqSchema: "ACMEDNS01ProviderConfigRequest", resSchema: "ACMEDNS01ProviderConfig", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "GET", path: "/api/v1/acme/dns-01/provider-configs", opID: "listACMEDNS01ProviderConfigs", summary: "List served ACME DNS-01 provider configs", handler: a.listACMEDNS01ProviderConfigs, resSchema: "ACMEDNS01ProviderConfigList", successCode: "200", perm: authz.IssuersRead},
		{method: "GET", path: "/api/v1/acme/dns-01/provider-configs/{id}", opID: "getACMEDNS01ProviderConfig", summary: "Get a served ACME DNS-01 provider config", handler: a.getACMEDNS01ProviderConfig, pathParams: dns01ProviderConfigPath, resSchema: "ACMEDNS01ProviderConfig", successCode: "200", perm: authz.IssuersRead},
		{method: "PUT", path: "/api/v1/acme/dns-01/provider-configs/{id}", opID: "updateACMEDNS01ProviderConfig", summary: "Replace a served ACME DNS-01 provider config using secret references", handler: a.updateACMEDNS01ProviderConfig, pathParams: dns01ProviderConfigPath, reqSchema: "ACMEDNS01ProviderConfigRequest", resSchema: "ACMEDNS01ProviderConfig", successCode: "200", mutation: true, perm: authz.IssuersWrite},
		{method: "DELETE", path: "/api/v1/acme/dns-01/provider-configs/{id}", opID: "deleteACMEDNS01ProviderConfig", summary: "Delete a served ACME DNS-01 provider config", handler: a.deleteACMEDNS01ProviderConfig, pathParams: dns01ProviderConfigPath, successCode: "204", mutation: true, perm: authz.IssuersWrite},
		{method: "POST", path: "/api/v1/acme/dns-01/preflight", opID: "preflightACMEDNS01", summary: "Run served DNS-01 propagation, CNAME, CAA, method, and wildcard policy preflight", handler: a.preflightACMEDNS01, reqSchema: "ACMEDNS01PreflightRequest", resSchema: "ACMEDNS01Preflight", successCode: "200", mutation: true, perm: authz.IssuersWrite},
		{method: "GET", path: "/api/v1/mdm/scep/status", opID: "getMDMSCEPStatus", summary: "Get served MDM SCEP policy and challenge telemetry status", handler: a.getMDMSCEPStatus, resSchema: "MDMSCEPStatus", successCode: "200", perm: authz.IssuersRead},
		{method: "POST", path: "/api/v1/mdm/scep/policies", opID: "createMDMSCEPPolicy", summary: "Create an MDM SCEP enrollment policy using reference-only trust anchors", handler: a.createMDMSCEPPolicy, reqSchema: "MDMSCEPPolicyRequest", resSchema: "MDMSCEPPolicy", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "GET", path: "/api/v1/mdm/scep/policies", opID: "listMDMSCEPPolicies", summary: "List MDM SCEP enrollment policies", handler: a.listMDMSCEPPolicies, resSchema: "MDMSCEPPolicyList", successCode: "200", perm: authz.IssuersRead},
		{method: "GET", path: "/api/v1/mdm/scep/policies/{id}", opID: "getMDMSCEPPolicy", summary: "Get an MDM SCEP enrollment policy", handler: a.getMDMSCEPPolicy, pathParams: idPath, resSchema: "MDMSCEPPolicy", successCode: "200", perm: authz.IssuersRead},
		{method: "PUT", path: "/api/v1/mdm/scep/policies/{id}", opID: "updateMDMSCEPPolicy", summary: "Replace an MDM SCEP enrollment policy", handler: a.updateMDMSCEPPolicy, pathParams: idPath, reqSchema: "MDMSCEPPolicyRequest", resSchema: "MDMSCEPPolicy", successCode: "200", mutation: true, perm: authz.IssuersWrite},
		{method: "DELETE", path: "/api/v1/mdm/scep/policies/{id}", opID: "deleteMDMSCEPPolicy", summary: "Delete an MDM SCEP enrollment policy", handler: a.deleteMDMSCEPPolicy, pathParams: idPath, successCode: "204", mutation: true, perm: authz.IssuersWrite},
		{method: "POST", path: "/api/v1/mdm/scep/policies/{id}/rotate-challenge", opID: "rotateMDMSCEPChallenge", summary: "Record MDM SCEP challenge rotation evidence", handler: a.rotateMDMSCEPChallenge, pathParams: idPath, resSchema: "MDMSCEPChallengeRotated", successCode: "200", mutation: true, perm: authz.IssuersWrite},
		{method: "GET", path: "/api/v1/external-cas", opID: "listExternalCAs", summary: "List configured upstream CA integrations", handler: a.listExternalCAs, resSchema: "ExternalCAList", successCode: "200", perm: authz.IssuersRead},
		{method: "POST", path: "/api/v1/external-cas/{id}/issue", opID: "issueExternalCA", summary: "Issue a certificate through a configured upstream CA", handler: a.issueExternalCA, pathParams: externalCAPath, reqSchema: "ExternalCAIssueRequest", resSchema: "ExternalCAIssuedCertificate", successCode: "201", mutation: true, perm: authz.CertsIssue, scope: combineRouteScopes(scopeIssuerPath("id"), scopeProfileJSON("profile_name"))},
		{method: "GET", path: "/api/v1/kubernetes/certificate-signing-requests", opID: "getKubernetesCSRSupport", summary: "Get native Kubernetes CertificateSigningRequest support", handler: a.getKubernetesCSRSupport, resSchema: "KubernetesCSRSupport", successCode: "200", perm: authz.CertsRead},
		{method: "GET", path: "/api/v1/kubernetes/trust-bundles", opID: "getKubernetesTrustBundleDistribution", summary: "Get Kubernetes trust-bundle distribution support", handler: a.getKubernetesTrustBundleDistribution, resSchema: "KubernetesTrustBundleDistribution", successCode: "200", perm: authz.CertsRead},
		{method: "POST", path: "/api/v1/workloads/attested-issuance", opID: "issueAttestedSVID", summary: "Issue an X.509-SVID after workload attestation", handler: a.issueAttestedSVID, reqSchema: "AttestedSVIDRequest", resSchema: "AttestedSVID", successCode: "201", mutation: true, perm: authz.CertsIssue},
		{method: "GET", path: "/api/v1/ssh/status", opID: "getSSHStatus", summary: "Get SSH CA, KRL, and attestation workflow status", handler: a.getSSHStatus, resSchema: "SSHStatus", successCode: "200", perm: authz.CertsRead},
		{method: "POST", path: "/api/v1/ssh/trust-rollouts", opID: "recordSSHTrustRollout", summary: "Record SSH trust rollout status from the agent-safe workflow", handler: a.recordSSHTrustRollout, reqSchema: "SSHTrustRolloutRequest", resSchema: "SSHTrustRollout", successCode: "201", mutation: true, perm: authz.AgentsWrite},
		{method: "POST", path: "/api/v1/ssh/attested-user-certs", opID: "issueAttestedSSHUserCert", summary: "Issue an attestation-gated SSH user certificate", handler: a.issueAttestedSSHUserCert, reqSchema: "SSHAttestedUserCertRequest", resSchema: "SSHAttestedUserCert", successCode: "201", mutation: true, perm: authz.CertsIssue},
		{method: "POST", path: "/api/v1/ssh/certificates/revoke", opID: "revokeSSHCertificate", summary: "Revoke an SSH certificate and publish KRL status", handler: a.revokeSSHCertificate, reqSchema: "SSHRevokeCertificateRequest", resSchema: "SSHStatus", successCode: "200", mutation: true, perm: authz.CertsWrite},
		{method: "POST", path: "/api/v1/ssh/hosts/retire", opID: "retireSSHHost", summary: "Record SSH host retirement evidence", handler: a.retireSSHHost, reqSchema: "SSHHostRetireRequest", resSchema: "SSHHostRetirement", successCode: "200", mutation: true, perm: authz.IdentitiesWrite},
		{method: "POST", path: "/api/v1/broker/agent-identities", opID: "issueBrokerAgentIdentity", summary: "Issue a policy-gated short-lived identity for an AI/MCP agent", handler: a.issueBrokerAgentIdentity, reqSchema: "BrokerAgentIdentityRequest", resSchema: "BrokerAgentIdentity", successCode: "201", mutation: true, perm: authz.CertsIssue},
		{method: "POST", path: "/api/v1/ephemeral", opID: "issueEphemeralCredential", summary: "Open or complete an attestation-gated JIT credential request", handler: a.issueEphemeralCredential, reqSchema: "EphemeralCredentialRequest", resSchema: "EphemeralCredential", successCode: "202", mutation: true, perm: authz.CertsRequest},
		{method: "POST", path: "/api/v1/ephemeral/api-keys", opID: "issueEphemeralAPIKey", summary: "Mint a short-TTL API key for machine workflows", handler: a.issueEphemeralAPIKey, reqSchema: "EphemeralAPIKeyRequest", resSchema: "EphemeralAPIKey", successCode: "201", mutation: true, sensitiveResponse: true, perm: authz.AccessWrite},
		{method: "POST", path: "/api/v1/ephemeral/{id}/approvals", opID: "approveEphemeralCredential", summary: "Approve a pending ephemeral JIT credential request", handler: a.approveEphemeralCredential, pathParams: ephemeralRequestPath, reqSchema: "EphemeralApprovalRequest", resSchema: "EphemeralApproval", successCode: "200", mutation: true, perm: authz.CertsIssue},

		{method: "POST", path: "/api/v1/identities", opID: "createIdentity", summary: "Create an identity", handler: a.createIdentity, reqSchema: "IdentityRequest", resSchema: "Identity", successCode: "201", mutation: true, perm: authz.IdentitiesWrite},
		{method: "GET", path: "/api/v1/identities", opID: "listIdentities", summary: "List identities", handler: a.listIdentities, query: page, resSchema: "IdentityList", successCode: "200", perm: authz.IdentitiesRead},
		{method: "POST", path: "/api/v1/identities/bulk-revoke", opID: "bulkRevokeIdentities", summary: "Bulk revoke identities by id or criteria", handler: a.bulkRevoke, reqSchema: "BulkRevokeRequest", resSchema: "BulkRevokeResult", successCode: "200", mutation: true, perm: authz.IdentitiesWrite},
		{method: "GET", path: "/api/v1/identities/{id}", opID: "getIdentity", summary: "Get an identity", handler: a.getIdentity, pathParams: idPath, resSchema: "Identity", successCode: "200", perm: authz.IdentitiesRead},
		{method: "POST", path: "/api/v1/identities/{id}/transitions", opID: "transitionIdentity", summary: "Apply a lifecycle transition", handler: a.transitionIdentity, pathParams: idPath, reqSchema: "TransitionRequest", resSchema: "Identity", successCode: "200", mutation: true, perm: authz.IdentitiesWrite},
		{method: "POST", path: "/api/v1/identities/{id}/approvals", opID: "approveIdentityAction", summary: "Approve a pending privileged action (dual control)", handler: a.approveIdentityAction, pathParams: idPath, reqSchema: "ApprovalRequest", resSchema: "Approval", successCode: "200", mutation: true, perm: authz.CertsIssue},
		{method: "GET", path: "/api/v1/nhi/inventory", opID: "listNHIInventory", summary: "List the unified non-human identity inventory across first-party and discovered credentials", handler: a.listNHIInventory, resSchema: "NHIInventory", successCode: "200", perm: authz.NHIRead},
		{method: "GET", path: "/api/v1/nhi/posture/shadow", opID: "listNHIShadowPosture", summary: "List shadow, unmanaged, and unregistered NHI posture findings", handler: a.listNHIShadowPosture, resSchema: "NHIShadowPosture", successCode: "200", perm: authz.NHIRead},
		{method: "GET", path: "/api/v1/nhi/policy/compliance", opID: "listNHIPolicyCompliance", summary: "List NHI policy compliance violations for rotation, scope, geography, expiry, and business purpose", handler: a.listNHIPolicyCompliance, resSchema: "NHIPolicyCompliance", successCode: "200", perm: authz.NHIRead},
		{method: "GET", path: "/api/v1/nhi/posture/overprivilege", opID: "listNHIOverPrivilegePosture", summary: "List over-privileged NHIs with usage-driven least-privilege recommendations", handler: a.listNHIOverPrivilegePosture, resSchema: "NHIOverPrivilegePosture", successCode: "200", perm: authz.NHIRead},
		{method: "GET", path: "/api/v1/nhi/posture/stale", opID: "listNHIStalePosture", summary: "List stale, unused, orphaned, and dormant NHI posture findings", handler: a.listNHIStalePosture, resSchema: "NHIStalePosture", successCode: "200", perm: authz.NHIRead},
		{method: "GET", path: "/api/v1/nhi/posture/static-credentials", opID: "listNHIStaticPosture", summary: "List long-lived and static NHI credential posture findings", handler: a.listNHIStaticPosture, resSchema: "NHIStaticPosture", successCode: "200", perm: authz.NHIRead},
		{method: "GET", path: "/api/v1/nhi/posture/exposure", opID: "listNHIExposurePosture", summary: "List internet-exposed and insecure-deployment NHI posture findings", handler: a.listNHIExposurePosture, resSchema: "NHIExposurePosture", successCode: "200", perm: authz.NHIRead},
		{method: "POST", path: "/api/v1/nhi/decommission", opID: "decommissionNHI", summary: "Decommission NHIs from departure, vendor-term, or inactivity signals", handler: a.decommissionNHI, reqSchema: "NHIDecommissionRequest", resSchema: "NHIDecommissionResponse", successCode: "200", mutation: true, perm: authz.IdentitiesWrite},
		{method: "GET", path: "/api/v1/ownership/attribution", opID: "listOwnershipAttribution", summary: "List NHI ownership attribution across human, team, vendor, and orphaned records", handler: a.listOwnershipAttribution, resSchema: "OwnershipAttribution", successCode: "200", perm: authz.NHIRead},
		{method: "POST", path: "/api/v1/policy/dry-run", opID: "dryRunPolicy", summary: "Validate and dry-run a candidate policy module with a bounded decision trace", handler: a.dryRunPolicy, reqSchema: "PolicyDryRunRequest", resSchema: "PolicyDryRun", successCode: "200", mutation: true, perm: authz.PolicyWrite},
		{method: "POST", path: "/api/v1/breakglass/issue", opID: "issueBreakglass", summary: "Issue and audit an online m-of-n break-glass certificate", handler: a.issueBreakglass, reqSchema: "BreakglassIssueRequest", resSchema: "BreakglassIssueResponse", successCode: "201", mutation: true, perm: authz.CertsIssue},
		{method: "POST", path: "/api/v1/breakglass/reconcile", opID: "reconcileBreakglass", summary: "Verify break-glass bundles and reconcile them into audit", handler: a.reconcileBreakglass, reqSchema: "BreakglassReconcileRequest", resSchema: "BreakglassReconcileResponse", successCode: "200", mutation: true, perm: authz.CertsIssue},

		{method: "POST", path: "/api/v1/certificates", opID: "ingestCertificate", summary: "Ingest a certificate into the inventory", handler: a.ingestCertificate, reqSchema: "CertificateIngest", resSchema: "Certificate", successCode: "201", mutation: true, perm: authz.CertsWrite},
		{method: "POST", path: "/api/v1/certificates/bulk-revoke", opID: "bulkRevokeCertificates", summary: "Bulk revoke certificate identities by id or criteria", handler: a.bulkRevoke, reqSchema: "BulkRevokeRequest", resSchema: "BulkRevokeResult", successCode: "200", mutation: true, perm: authz.IdentitiesWrite},
		{method: "GET", path: "/api/v1/certificates", opID: "listCertificates", summary: "Query the certificate inventory", handler: a.listCertificates, query: certQuery, resSchema: "CertificateList", successCode: "200", perm: authz.CertsRead},
		{method: "GET", path: "/api/v1/certificates/health", opID: "getCertificateHealth", summary: "Get estate-wide certificate expiry and source health", handler: a.getCertificateHealth, resSchema: "CertificateHealthDashboard", successCode: "200", perm: authz.CertsRead},
		{method: "GET", path: "/api/v1/revocation/crls", opID: "listCRLDistributions", summary: "List published full, sharded, and delta CRL distribution artifacts", handler: a.listCRLDistributions, resSchema: "CRLDistributionList", successCode: "200", perm: authz.CertsRead},
		{method: "POST", path: "/api/v1/revocation/ct-submissions", opID: "submitCertificateTransparency", summary: "Queue precertificate and certificate submission to Certificate Transparency logs", handler: a.submitCertificateTransparency, reqSchema: "CTLogSubmissionRequest", resSchema: "CTLogSubmission", successCode: "202", mutation: true, perm: authz.CertsWrite},
		{method: "GET", path: "/api/v1/certificates/{id}", opID: "getCertificate", summary: "Get an inventoried certificate", handler: a.getCertificate, pathParams: idPath, resSchema: "Certificate", successCode: "200", perm: authz.CertsRead},

		{method: "POST", path: "/api/v1/discovery/sources", opID: "createDiscoverySource", summary: "Create a discovery source", handler: a.createDiscoverySource, reqSchema: "DiscoverySourceRequest", resSchema: "DiscoverySource", successCode: "201", mutation: true, perm: authz.DiscoveryWrite},
		{method: "GET", path: "/api/v1/discovery/sources", opID: "listDiscoverySources", summary: "List discovery sources", handler: a.listDiscoverySources, query: page, resSchema: "DiscoverySourceList", successCode: "200", perm: authz.DiscoveryRead},
		{method: "POST", path: "/api/v1/discovery/schedules", opID: "createDiscoverySchedule", summary: "Create a discovery schedule", handler: a.createDiscoverySchedule, reqSchema: "DiscoveryScheduleRequest", resSchema: "DiscoverySchedule", successCode: "201", mutation: true, perm: authz.DiscoveryWrite},
		{method: "GET", path: "/api/v1/discovery/schedules", opID: "listDiscoverySchedules", summary: "List discovery schedules", handler: a.listDiscoverySchedules, query: page, resSchema: "DiscoveryScheduleList", successCode: "200", perm: authz.DiscoveryRead},
		{method: "POST", path: "/api/v1/discovery/runs", opID: "startDiscoveryRun", summary: "Start a discovery run", handler: a.startDiscoveryRun, reqSchema: "DiscoveryRunRequest", resSchema: "DiscoveryRun", successCode: "201", mutation: true, perm: authz.DiscoveryWrite},
		{method: "GET", path: "/api/v1/discovery/runs", opID: "listDiscoveryRuns", summary: "List discovery runs", handler: a.listDiscoveryRuns, query: page, resSchema: "DiscoveryRunList", successCode: "200", perm: authz.DiscoveryRead},
		{method: "GET", path: "/api/v1/discovery/runs/{id}", opID: "getDiscoveryRun", summary: "Get a discovery run", handler: a.getDiscoveryRun, pathParams: idPath, resSchema: "DiscoveryRun", successCode: "200", perm: authz.DiscoveryRead},
		{method: "GET", path: "/api/v1/discovery/monitoring", opID: "getDiscoveryMonitoring", summary: "Get continuous monitoring and centralized inventory posture", handler: a.listDiscoveryMonitoring, resSchema: "DiscoveryMonitoring", successCode: "200", perm: authz.DiscoveryRead},
		{method: "GET", path: "/api/v1/discovery/findings", opID: "listDiscoveryFindings", summary: "List discovery findings", handler: a.listDiscoveryFindings, query: discoveryFindingQuery, resSchema: "DiscoveryFindingList", successCode: "200", perm: authz.DiscoveryRead},
		{method: "POST", path: "/api/v1/discovery/findings/{id}/claim", opID: "claimDiscoveryFinding", summary: "Claim a discovery finding as managed", handler: a.claimDiscoveryFinding, pathParams: idPath, reqSchema: "DiscoveryFindingTriageRequest", resSchema: "DiscoveryFinding", successCode: "200", mutation: true, perm: authz.DiscoveryWrite},
		{method: "POST", path: "/api/v1/discovery/findings/{id}/dismiss", opID: "dismissDiscoveryFinding", summary: "Dismiss a discovery finding", handler: a.dismissDiscoveryFinding, pathParams: idPath, reqSchema: "DiscoveryFindingTriageRequest", resSchema: "DiscoveryFinding", successCode: "200", mutation: true, perm: authz.DiscoveryWrite},

		{method: "GET", path: "/api/v1/connectors/catalog", opID: "listConnectorCatalog", summary: "List served connector kinds and rollback posture", handler: a.listConnectorCatalog, resSchema: "ConnectorCatalog", successCode: "200", perm: authz.ConnectorsRead},
		{method: "POST", path: "/api/v1/connectors/targets", opID: "createConnectorTarget", summary: "Create a tenant-scoped deployment connector target", handler: a.createConnectorTarget, reqSchema: "DeploymentTargetRequest", resSchema: "DeploymentTarget", successCode: "201", mutation: true, perm: authz.ConnectorsWrite},
		{method: "GET", path: "/api/v1/connectors/targets", opID: "listConnectorTargets", summary: "List tenant-scoped deployment connector targets", handler: a.listConnectorTargets, resSchema: "DeploymentTargetList", successCode: "200", perm: authz.ConnectorsRead},
		{method: "GET", path: "/api/v1/connectors/targets/{id}", opID: "getConnectorTarget", summary: "Get a deployment connector target", handler: a.getConnectorTarget, pathParams: idPath, resSchema: "DeploymentTarget", successCode: "200", perm: authz.ConnectorsRead},
		{method: "PUT", path: "/api/v1/connectors/targets/{id}", opID: "updateConnectorTarget", summary: "Update a deployment connector target", handler: a.updateConnectorTarget, pathParams: idPath, reqSchema: "DeploymentTargetRequest", resSchema: "DeploymentTarget", successCode: "200", mutation: true, perm: authz.ConnectorsWrite},
		{method: "DELETE", path: "/api/v1/connectors/targets/{id}", opID: "deleteConnectorTarget", summary: "Delete a deployment connector target", handler: a.deleteConnectorTarget, pathParams: idPath, successCode: "204", mutation: true, perm: authz.ConnectorsWrite},
		{method: "POST", path: "/api/v1/connectors/targets/{id}/test", opID: "testConnectorTarget", summary: "Validate a deployment connector target", handler: a.testConnectorTarget, pathParams: idPath, resSchema: "ConnectorDelivery", successCode: "200", mutation: true, perm: authz.ConnectorsWrite},
		{method: "POST", path: "/api/v1/connectors/targets/{id}/deploy", opID: "deployConnectorTarget", summary: "Deploy an issued identity through a deployment connector target", handler: a.deployConnectorTarget, pathParams: idPath, reqSchema: "ConnectorTargetActionRequest", resSchema: "Identity", successCode: "200", mutation: true, perm: authz.ConnectorsWrite},
		{method: "POST", path: "/api/v1/connectors/targets/{id}/rollback", opID: "rollbackConnectorTarget", summary: "Record rollback evidence for a deployment connector target", handler: a.rollbackConnectorTarget, pathParams: idPath, reqSchema: "ConnectorTargetActionRequest", resSchema: "ConnectorDelivery", successCode: "200", mutation: true, perm: authz.ConnectorsWrite},
		{method: "POST", path: "/api/v1/identities/{id}/connector-target", opID: "bindIdentityConnectorTarget", summary: "Bind an identity to a deployment connector target", handler: a.bindIdentityConnectorTarget, pathParams: idPath, reqSchema: "IdentityConnectorTargetRequest", resSchema: "Identity", successCode: "200", mutation: true, perm: authz.ConnectorsWrite},
		{method: "GET", path: "/api/v1/connectors/outbox-circuits", opID: "listOutboxCircuits", summary: "List outbox destination circuit breaker state", handler: a.listOutboxCircuits, resSchema: "OutboxCircuitList", successCode: "200", perm: authz.ConnectorsRead},
		{method: "GET", path: "/api/v1/notification-channels", opID: "listNotificationChannels", summary: "List supported and configured notification channels", handler: a.listNotificationChannels, resSchema: "NotificationChannelList", successCode: "200", perm: authz.NotificationsRead},
		{method: "POST", path: "/api/v1/notification-channels/{id}/test", opID: "testNotificationChannel", summary: "Queue a notification channel test", handler: a.testNotificationChannel, pathParams: notificationChannelPath, reqSchema: "NotificationChannelTestRequest", resSchema: "NotificationChannelTest", successCode: "202", mutation: true, perm: authz.NotificationsWrite},
		{method: "POST", path: "/api/v1/notification-routing-policies", opID: "createNotificationRoutingPolicy", summary: "Create a notification routing policy", handler: a.createNotificationRoutingPolicy, reqSchema: "NotificationRoutingPolicyRequest", resSchema: "NotificationRoutingPolicy", successCode: "201", mutation: true, perm: authz.NotificationsWrite},
		{method: "GET", path: "/api/v1/notification-routing-policies", opID: "listNotificationRoutingPolicies", summary: "List notification routing policies", handler: a.listNotificationRoutingPolicies, resSchema: "NotificationRoutingPolicyList", successCode: "200", perm: authz.NotificationsRead},
		{method: "GET", path: "/api/v1/notification-routing-policies/{id}", opID: "getNotificationRoutingPolicy", summary: "Get a notification routing policy", handler: a.getNotificationRoutingPolicy, pathParams: notificationRoutingPolicyPath, resSchema: "NotificationRoutingPolicy", successCode: "200", perm: authz.NotificationsRead},
		{method: "PUT", path: "/api/v1/notification-routing-policies/{id}", opID: "updateNotificationRoutingPolicy", summary: "Update a notification routing policy", handler: a.updateNotificationRoutingPolicy, pathParams: notificationRoutingPolicyPath, reqSchema: "NotificationRoutingPolicyRequest", resSchema: "NotificationRoutingPolicy", successCode: "200", mutation: true, perm: authz.NotificationsWrite},
		{method: "DELETE", path: "/api/v1/notification-routing-policies/{id}", opID: "deleteNotificationRoutingPolicy", summary: "Delete a notification routing policy", handler: a.deleteNotificationRoutingPolicy, pathParams: notificationRoutingPolicyPath, successCode: "204", mutation: true, perm: authz.NotificationsWrite},
		{method: "GET", path: "/api/v1/notifications", opID: "listNotifications", summary: "List notification inbox and dead-letter rows", handler: a.listNotifications, query: notificationQuery, resSchema: "NotificationList", successCode: "200", perm: authz.NotificationsRead},
		{method: "POST", path: "/api/v1/notifications/{id}/read", opID: "markNotificationRead", summary: "Mark a notification as read", handler: a.markNotificationRead, pathParams: notificationIDPath, resSchema: "Notification", successCode: "200", mutation: true, perm: authz.NotificationsWrite},
		{method: "POST", path: "/api/v1/notifications/{id}/requeue", opID: "requeueNotification", summary: "Requeue a dead-lettered notification dispatch", handler: a.requeueNotification, pathParams: notificationIDPath, resSchema: "Notification", successCode: "200", mutation: true, perm: authz.NotificationsWrite},
		{method: "GET", path: "/api/v1/notifications/{id}", opID: "getNotification", summary: "Get a notification inbox row", handler: a.getNotification, pathParams: notificationIDPath, resSchema: "Notification", successCode: "200", perm: authz.NotificationsRead},
		{method: "GET", path: "/api/v1/connectors/deliveries", opID: "listConnectorDeliveries", summary: "List connector delivery receipts", handler: a.listConnectorDeliveries, query: identityScopedPage, resSchema: "ConnectorDeliveryList", successCode: "200", perm: authz.ConnectorsRead},
		{method: "GET", path: "/api/v1/connectors/deliveries/{id}", opID: "getConnectorDelivery", summary: "Get a connector delivery receipt", handler: a.getConnectorDelivery, pathParams: idPath, resSchema: "ConnectorDelivery", successCode: "200", perm: authz.ConnectorsRead},
		{method: "POST", path: "/api/v1/lifecycle/endpoint-bindings", opID: "createEndpointBinding", summary: "Create an automated enrollment-to-endpoint binding", handler: a.createEndpointBinding, reqSchema: "EndpointBindingRequest", resSchema: "EndpointBinding", successCode: "201", mutation: true, perm: authz.ConnectorsWrite},
		{method: "GET", path: "/api/v1/lifecycle/rotation-runs", opID: "listRotationRuns", summary: "List lifecycle rotation runs", handler: a.listRotationRuns, query: identityScopedPage, resSchema: "RotationRunList", successCode: "200", perm: authz.LifecycleRead},
		{method: "GET", path: "/api/v1/lifecycle/rotation-runs/{id}", opID: "getRotationRun", summary: "Get a lifecycle rotation run", handler: a.getRotationRun, pathParams: idPath, resSchema: "RotationRun", successCode: "200", perm: authz.LifecycleRead},

		{method: "POST", path: "/api/v1/incidents/executions", opID: "executeIncident", summary: "Execute a credential-compromise incident remediation", handler: a.executeIncident, reqSchema: "IncidentExecutionRequest", resSchema: "IncidentExecution", successCode: "201", mutation: true, perm: authz.IncidentsWrite},
		{method: "POST", path: "/api/v1/incidents/fleet-reissuance-runs", opID: "startFleetReissuance", summary: "Run compromised-issuer fleet reissuance", handler: a.startFleetReissuance, reqSchema: "FleetReissuanceRequest", resSchema: "FleetReissuanceRun", successCode: "201", mutation: true, perm: authz.IncidentsWrite},
		{method: "POST", path: "/api/v1/itsm/servicenow/tickets", opID: "createServiceNowTicket", summary: "Queue a ServiceNow ITSM ticket through the outbox", handler: a.createServiceNowTicket, reqSchema: "ServiceNowTicketRequest", resSchema: "ITSMTicket", successCode: "202", mutation: true, perm: authz.IncidentsWrite},
		{method: "POST", path: "/api/v1/incidents/response-integrations/dispatch", opID: "dispatchResponseIntegrations", summary: "Dispatch an incident response packet to SIEM, SOAR, chat, and ITSM integrations", handler: a.dispatchResponseIntegrations, reqSchema: "ResponseIntegrationDispatchRequest", resSchema: "ResponseIntegrationDispatch", successCode: "202", mutation: true, perm: authz.IncidentsWrite},
		{method: "GET", path: "/api/v1/incidents/executions", opID: "listIncidentExecutions", summary: "List incident execution evidence packs", handler: a.listIncidentExecutions, query: incidentScopedPage, resSchema: "IncidentExecutionList", successCode: "200", perm: authz.IncidentsRead},
		{method: "GET", path: "/api/v1/incidents/executions/{id}", opID: "getIncidentExecution", summary: "Get an incident execution evidence pack", handler: a.getIncidentExecution, pathParams: idPath, resSchema: "IncidentExecution", successCode: "200", perm: authz.IncidentsRead},
		{method: "GET", path: "/api/v1/incidents/fleet-reissuance-runs", opID: "listFleetReissuanceRuns", summary: "List compromised-issuer fleet reissuance runs", handler: a.listFleetReissuanceRuns, query: issuerScopedPage, resSchema: "FleetReissuanceRunList", successCode: "200", perm: authz.IncidentsRead},
		{method: "GET", path: "/api/v1/incidents/fleet-reissuance-runs/{id}", opID: "getFleetReissuanceRun", summary: "Get a fleet reissuance run evidence pack", handler: a.getFleetReissuanceRun, pathParams: idPath, resSchema: "FleetReissuanceRun", successCode: "200", perm: authz.IncidentsRead},
		{method: "POST", path: "/api/v1/incidents/fleet-reissuance-runs/{id}/pause", opID: "pauseFleetReissuance", summary: "Record pause evidence for a fleet reissuance run", handler: a.pauseFleetReissuance, pathParams: idPath, reqSchema: "FleetReissuanceActionRequest", resSchema: "FleetReissuanceRun", successCode: "200", mutation: true, perm: authz.IncidentsWrite},
		{method: "POST", path: "/api/v1/incidents/fleet-reissuance-runs/{id}/resume", opID: "resumeFleetReissuance", summary: "Record resume evidence for a fleet reissuance run", handler: a.resumeFleetReissuance, pathParams: idPath, reqSchema: "FleetReissuanceActionRequest", resSchema: "FleetReissuanceRun", successCode: "200", mutation: true, perm: authz.IncidentsWrite},
		{method: "POST", path: "/api/v1/incidents/fleet-reissuance-runs/{id}/rollback", opID: "rollbackFleetReissuance", summary: "Record rollback evidence for a fleet reissuance run", handler: a.rollbackFleetReissuance, pathParams: idPath, reqSchema: "FleetReissuanceActionRequest", resSchema: "FleetReissuanceRun", successCode: "200", mutation: true, perm: authz.IncidentsWrite},
		{method: "GET", path: "/api/v1/incidents/fleet-reissuance-runs/{id}/evidence", opID: "exportFleetReissuanceEvidence", summary: "Export fleet reissuance evidence", handler: a.exportFleetReissuanceEvidence, pathParams: idPath, resSchema: "FleetReissuanceEvidence", successCode: "200", perm: authz.IncidentsRead},
		{method: "GET", path: "/api/v1/remediation/playbooks", opID: "listRemediationPlaybooks", summary: "List automated remediation playbooks", handler: a.listRemediationPlaybooks, resSchema: "RemediationPlaybookCatalog", successCode: "200", perm: authz.IncidentsRead},
		{method: "POST", path: "/api/v1/remediation/playbooks/{id}/runs", opID: "runRemediationPlaybook", summary: "Run an automated remediation playbook", handler: a.runRemediationPlaybook, pathParams: playbookIDPath, reqSchema: "RemediationPlaybookRunRequest", resSchema: "RemediationPlaybookRun", successCode: "201", mutation: true, perm: authz.IncidentsWrite},
		{method: "GET", path: "/api/v1/remediation/playbook-runs", opID: "listRemediationPlaybookRuns", summary: "List remediation playbook run evidence", handler: a.listRemediationPlaybookRuns, query: playbookScopedPage, resSchema: "RemediationPlaybookRunList", successCode: "200", perm: authz.IncidentsRead},
		{method: "GET", path: "/api/v1/remediation/playbook-runs/{id}", opID: "getRemediationPlaybookRun", summary: "Get a remediation playbook run evidence pack", handler: a.getRemediationPlaybookRun, pathParams: idPath, resSchema: "RemediationPlaybookRun", successCode: "200", perm: authz.IncidentsRead},
		{method: "GET", path: "/api/v1/remediation/owner-actions", opID: "listOwnerRemediationActions", summary: "List owner-driven self-remediation actions", handler: a.listOwnerRemediationActions, query: []param{{name: "owner_id", typ: "string", desc: "return only actions for one owner id"}}, resSchema: "OwnerRemediationQueue", successCode: "200", perm: authz.OwnersRead},
		{method: "POST", path: "/api/v1/remediation/owner-actions/{id}/accept", opID: "acceptOwnerRemediationAction", summary: "Accept an owner-driven self-remediation action", handler: a.acceptOwnerRemediationAction, pathParams: idPath, reqSchema: "OwnerRemediationAcceptRequest", resSchema: "OwnerRemediationRun", successCode: "201", mutation: true, perm: authz.OwnersWrite},

		{method: "GET", path: "/api/v1/access/roles", opID: "listAccessRoles", summary: "List built-in and configured access roles", handler: a.listAccessRoles, resSchema: "RoleList", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/access/oidc-mapping", opID: "getOIDCMappingStatus", summary: "Show served OIDC tenant and group mapping status", handler: a.getOIDCMappingStatus, resSchema: "OIDCMappingStatus", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/access/members", opID: "listMembers", summary: "List tenant members and offboarding state", handler: a.listMembers, query: memberQuery, resSchema: "MemberList", successCode: "200", perm: authz.AccessRead},
		{method: "PUT", path: "/api/v1/access/members/{subject}", opID: "upsertMember", summary: "Onboard or update a tenant member", handler: a.upsertMember, pathParams: memberSubjectPath, reqSchema: "MemberRequest", resSchema: "Member", successCode: "200", mutation: true, perm: authz.AccessWrite},
		{method: "POST", path: "/api/v1/access/members/{subject}/offboard", opID: "offboardMember", summary: "Offboard a tenant member and revoke their API tokens", handler: a.offboardMember, pathParams: memberSubjectPath, reqSchema: "OffboardMemberRequest", resSchema: "OffboardMemberResponse", successCode: "200", mutation: true, perm: authz.AccessWrite},
		{method: "GET", path: "/api/v1/access/api-tokens", opID: "listAPITokens", summary: "List API token metadata", handler: a.listAPITokens, query: apiTokenQuery, resSchema: "APITokenList", successCode: "200", perm: authz.AccessRead},
		{method: "POST", path: "/api/v1/access/api-tokens", opID: "createAPIToken", summary: "Mint a tenant-scoped API token for a member", handler: a.createAPIToken, reqSchema: "APITokenCreateRequest", resSchema: "APITokenCreateResponse", successCode: "201", mutation: true, sensitiveResponse: true, perm: authz.AccessWrite},
		{method: "DELETE", path: "/api/v1/access/api-tokens/{id}", opID: "revokeAPIToken", summary: "Revoke an API token", handler: a.revokeAPIToken, pathParams: idPath, successCode: "204", mutation: true, perm: authz.AccessWrite},
		{method: "GET", path: "/api/v1/access/sessions", opID: "listPAMSessions", summary: "List just-in-time privileged access sessions", handler: a.listPAMSessions, query: page, resSchema: "PAMSessionList", successCode: "200", sensitiveResponse: true, perm: authz.AccessRead},
		{method: "POST", path: "/api/v1/access/sessions", opID: "openPAMSession", summary: "Open a just-in-time privileged access session", handler: a.openPAMSession, reqSchema: "PAMSessionRequest", resSchema: "PAMSession", successCode: "201", mutation: true, sensitiveResponse: true, perm: authz.AccessWrite},
		{method: "GET", path: "/api/v1/access/sessions/{id}", opID: "getPAMSession", summary: "Get a privileged access session", handler: a.getPAMSession, pathParams: idPath, resSchema: "PAMSession", successCode: "200", sensitiveResponse: true, perm: authz.AccessRead},
		{method: "POST", path: "/api/v1/access/requests", opID: "createAccessChangeRequest", summary: "Create an NHI access-change request with PR/change evidence", handler: a.createAccessChangeRequest, reqSchema: "AccessChangeRequestCreateRequest", resSchema: "AccessChangeRequest", successCode: "201", mutation: true, perm: authz.AccessWrite},
		{method: "GET", path: "/api/v1/access/requests", opID: "listAccessChangeRequests", summary: "List NHI access-change requests", handler: a.listAccessChangeRequests, query: page, resSchema: "AccessChangeRequestList", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/access/requests/{id}", opID: "getAccessChangeRequest", summary: "Get an NHI access-change request", handler: a.getAccessChangeRequest, pathParams: idPath, resSchema: "AccessChangeRequest", successCode: "200", perm: authz.AccessRead},
		{method: "POST", path: "/api/v1/access/requests/{id}/decisions", opID: "decideAccessChangeRequest", summary: "Approve or deny an NHI access-change request", handler: a.decideAccessChangeRequest, pathParams: idPath, reqSchema: "AccessChangeDecisionRequest", resSchema: "AccessChangeRequest", successCode: "200", mutation: true, perm: authz.AccessWrite},
		{method: "POST", path: "/api/v1/access/reviews", opID: "startNHIReviewCampaign", summary: "Start an NHI access certification campaign", handler: a.startNHIReviewCampaign, reqSchema: "NHIReviewCampaignStartRequest", resSchema: "NHIReviewCampaign", successCode: "201", mutation: true, perm: authz.AccessWrite},
		{method: "GET", path: "/api/v1/access/reviews", opID: "listNHIReviewCampaigns", summary: "List NHI access certification campaigns", handler: a.listNHIReviewCampaigns, query: page, resSchema: "NHIReviewCampaignList", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/access/reviews/{id}", opID: "getNHIReviewCampaign", summary: "Get an NHI access certification campaign", handler: a.getNHIReviewCampaign, pathParams: idPath, resSchema: "NHIReviewCampaign", successCode: "200", perm: authz.AccessRead},
		{method: "POST", path: "/api/v1/access/reviews/{id}/items/{item_id}/decision", opID: "decideNHIReviewItem", summary: "Record an NHI access-review item decision", handler: a.decideNHIReviewItem, pathParams: nhiReviewItemPath, reqSchema: "NHIReviewDecisionRequest", resSchema: "NHIReviewCampaign", successCode: "200", mutation: true, perm: authz.AccessWrite},

		{method: "POST", path: "/api/v1/profiles", opID: "createProfile", summary: "Create a certificate profile version", handler: a.createProfile, reqSchema: "ProfileRequest", resSchema: "Profile", successCode: "201", mutation: true, perm: authz.ProfilesWrite, scope: scopeProfileJSON("name")},
		{method: "GET", path: "/api/v1/profiles", opID: "listProfiles", summary: "List active certificate profiles", handler: a.listProfiles, resSchema: "ProfileList", successCode: "200", perm: authz.ProfilesRead},
		{method: "GET", path: "/api/v1/profiles/{name}/versions/{version}", opID: "getProfileVersion", summary: "Get a certificate-profile version", handler: a.getProfileVersion, pathParams: profileVersionPath, resSchema: "Profile", successCode: "200", perm: authz.ProfilesRead, scope: scopeProfilePath("name")},

		{method: "GET", path: "/api/v1/audit/events", opID: "searchAudit", summary: "Query the audit log", handler: a.searchAudit, query: auditQuery, resSchema: "AuditEventList", successCode: "200", perm: authz.AuditRead},
		{method: "GET", path: "/api/v1/audit/export", opID: "exportAudit", summary: "Export a signed audit evidence bundle", handler: a.exportAudit, query: auditQuery, resSchema: "AuditBundle", successCode: "200", perm: authz.AuditRead},
		{method: "GET", path: "/api/v1/compliance/inventory-report", opID: "getComplianceInventoryReport", summary: "Get compliance and inventory reporting coverage", handler: a.getComplianceInventoryReport, resSchema: "ComplianceInventoryReport", successCode: "200", perm: authz.AuditRead},
		{method: "GET", path: "/api/v1/compliance/nhi-report", opID: "getNHIComplianceReport", summary: "Get audit-ready NHI compliance mappings", handler: a.getNHIComplianceReport, resSchema: "NHIComplianceReport", successCode: "200", perm: authz.AuditRead},
		{method: "POST", path: "/api/v1/compliance/report-schedules", opID: "createComplianceReportSchedule", summary: "Create a scheduled compliance or inventory report", handler: a.createComplianceReportSchedule, reqSchema: "ComplianceReportScheduleRequest", resSchema: "ComplianceReportSchedule", successCode: "201", mutation: true, perm: authz.AuditWrite},
		{method: "GET", path: "/api/v1/compliance/report-schedules", opID: "listComplianceReportSchedules", summary: "List scheduled compliance and inventory reports", handler: a.listComplianceReportSchedules, query: page, resSchema: "ComplianceReportScheduleList", successCode: "200", perm: authz.AuditRead},
		{method: "GET", path: "/api/v1/compliance/evidence-packs/{framework}", opID: "getComplianceEvidencePack", summary: "Export a signed framework compliance evidence pack", handler: a.getComplianceEvidencePack, pathParams: complianceFrameworkPath, resSchema: "ComplianceEvidencePack", successCode: "200", perm: authz.AuditRead},

		{method: "POST", path: "/api/v1/privacy/subject-erasures", opID: "erasePrivacySubject", summary: "Erase direct subject personal data from tenant read surfaces", handler: a.erasePrivacySubject, reqSchema: "PrivacySubjectErasureRequest", resSchema: "PrivacySubjectErasure", successCode: "201", mutation: true, perm: authz.PrivacyWrite},
		{method: "GET", path: "/api/v1/privacy/subject-erasures", opID: "listPrivacySubjectErasures", summary: "List subject-erasure evidence", handler: a.listPrivacySubjectErasures, query: privacyErasureQuery, resSchema: "PrivacySubjectErasureList", successCode: "200", perm: authz.PrivacyRead},
		{method: "POST", path: "/api/v1/privacy/retention-runs", opID: "enforcePrivacyRetention", summary: "Run non-audit personal-data retention", handler: a.enforcePrivacyRetention, resSchema: "PrivacyRetentionRun", successCode: "201", mutation: true, perm: authz.PrivacyWrite},
		{method: "GET", path: "/api/v1/privacy/retention-runs", opID: "listPrivacyRetentionRuns", summary: "List non-audit retention evidence", handler: a.listPrivacyRetentionRuns, query: privacyRetentionQuery, resSchema: "PrivacyRetentionRunList", successCode: "200", perm: authz.PrivacyRead},
		{method: "POST", path: "/api/v1/privacy/subject-exports", opID: "exportPrivacySubject", summary: "Export all records tied to a data subject (access/portability, read-only)", handler: a.exportPrivacySubject, reqSchema: "PrivacySubjectExportRequest", resSchema: "PrivacySubjectExport", successCode: "200", perm: authz.PrivacyRead},
		{method: "GET", path: "/api/v1/privacy/catalog", opID: "getPrivacyCatalog", summary: "Get the maintained personal-data catalog", handler: a.getPrivacyCatalog, resSchema: "PrivacyCatalog", successCode: "200", perm: authz.PrivacyRead},

		{method: "GET", path: "/api/v1/graph", opID: "getGraph", summary: "Get the credential graph", handler: a.getGraph, resSchema: "GraphResponse", successCode: "200", perm: authz.GraphRead},
		{method: "GET", path: "/api/v1/graph/reachable/{id}", opID: "graphReachable", summary: "Nodes reachable from a node (reachability query)", handler: a.graphReachable, pathParams: graphNodePath, resSchema: "GraphReachable", successCode: "200", perm: authz.GraphRead},
		{method: "GET", path: "/api/v1/graph/blast-radius/{id}", opID: "graphBlastRadius", summary: "Blast radius of compromising a node", handler: a.graphBlastRadius, pathParams: graphNodePath, resSchema: "GraphImpact", successCode: "200", perm: authz.GraphRead},
		{method: "POST", path: "/api/v1/graph/query", opID: "graphQuery", summary: "Run a Cypher-style graph query", handler: a.graphQuery, resSchema: "GraphQueryResult", successCode: "200", perm: authz.GraphRead},

		{method: "GET", path: "/api/v1/risk/credentials", opID: "listRiskScores", summary: "Rank credentials by composite risk score", handler: a.listRiskScores, resSchema: "CredentialRiskList", successCode: "200", perm: authz.RiskRead},
		{method: "GET", path: "/api/v1/risk/contextual-priorities", opID: "listContextualRiskPriorities", summary: "Prioritize credential risk with blast-radius context", handler: a.listContextualRiskPriorities, resSchema: "ContextualRiskPriorities", successCode: "200", perm: authz.RiskRead},
		{method: "POST", path: "/api/v1/cbom/scans", opID: "startCBOMScan", summary: "Scan TLS endpoints and host crypto config into the CBOM inventory", handler: a.startCBOMScan, reqSchema: "CBOMScanRequest", resSchema: "CBOMScan", successCode: "201", mutation: true, perm: authz.DiscoveryWrite},
		{method: "GET", path: "/api/v1/cbom/assets", opID: "listCBOMAssets", summary: "List CBOM assets with PQC migration targets and progress", handler: a.listCBOMAssets, resSchema: "CBOMInventory", successCode: "200", perm: authz.RiskRead},
		{method: "POST", path: "/api/v1/pqc/migrations", opID: "startPQCMigration", summary: "Queue PQC re-issuance for CBOM assets through the served protocol path", handler: a.startPQCMigration, reqSchema: "PQCMigrationRequest", resSchema: "PQCMigration", successCode: "202", mutation: true, perm: authz.CertsIssue},
		{method: "POST", path: "/api/v1/pqc/migrations/{run_id}/rollback", opID: "rollbackPQCMigration", summary: "Queue rollback for a PQC migration run", handler: a.rollbackPQCMigration, pathParams: pqcMigrationRunPath, reqSchema: "PQCMigrationRollbackRequest", resSchema: "PQCMigrationRollback", successCode: "202", mutation: true, perm: authz.CertsIssue},

		// Served AI / RCA / NL-query / MCP surface (SURFACE-003; F75/F76/F77/F78). All
		// READ-ONLY and tenant-scoped: the tenant + RBAC scope come from the
		// authenticated principal (never a request field), reads run under RLS (AN-1),
		// and any model egress is redacted + residual-entropy-refused before it leaves
		// (AN-8). POST is used for ai/query, ai/rca, and an MCP tool call because the
		// typed request/subject travels in the body, but none is a mutation (no
		// Idempotency-Key, like the graph query). The surface fails closed (503) unless
		// the server wires WithAISurface. RBAC is graph:read for the query/RCA/MCP routes
		// (the AI surface is a read consumer of the credential graph + inventory).
		{method: "GET", path: "/api/v1/ai/status", opID: "aiStatus", summary: "Report the served AI runtime/model posture without leaking model endpoint secrets", handler: a.aiStatus, resSchema: "AIStatus", successCode: "200", perm: authz.GraphRead},
		{method: "POST", path: "/api/v1/ai/query", opID: "aiQuery", summary: "Answer a typed semantic/NL query over the tenant's data (read-only, grounded)", handler: a.aiQuery, reqSchema: "AIQueryRequest", resSchema: "AIAnswer", successCode: "200", perm: authz.GraphRead},
		{method: "POST", path: "/api/v1/ai/rca", opID: "aiRCA", summary: "Answer a grounded root-cause / NL question from cited tenant records (read-only)", handler: a.aiRCA, reqSchema: "RCARequest", resSchema: "AIAnswer", successCode: "200", perm: authz.GraphRead},
		{method: "GET", path: "/api/v1/mcp/tools", opID: "listMCPTools", summary: "List the read-only, tenant-scoped MCP tools an AI agent may call", handler: a.mcpTools, resSchema: "MCPToolList", successCode: "200", perm: authz.GraphRead},
		{method: "POST", path: "/api/v1/mcp/tools/{tool}", opID: "callMCPTool", summary: "Invoke one MCP tool (read by default; guarded writes when enabled)", handler: a.mcpCall, pathParams: mcpToolPath, reqSchema: "MCPToolCall", resSchema: "MCPToolResult", successCode: "200", perm: authz.GraphRead},

		{method: "GET", path: "/api/v1/agents", opID: "listAgents", summary: "List in-network agents", handler: a.listAgents, query: page, resSchema: "AgentList", successCode: "200", perm: authz.AgentsRead},
		{method: "POST", path: "/api/v1/agents/enrollment-tokens", opID: "createEnrollmentToken", summary: "Mint a one-time agent bootstrap token", handler: a.createEnrollmentToken, resSchema: "EnrollmentToken", successCode: "201", mutation: true, sensitiveResponse: true, perm: authz.AgentsWrite},
		{method: "POST", path: "/api/v1/agents/{id}/cert-revocations", opID: "revokeAgentCertificate", summary: "Revoke an agent mTLS certificate", handler: a.revokeAgentCertificate, pathParams: idPath, reqSchema: "AgentCertRevocationRequest", resSchema: "AgentCertRevocation", successCode: "201", mutation: true, perm: authz.AgentsWrite},

		// Served secrets/identity surface (GAP-006): the secret store (CRUD + rotation,
		// secretsdk/F64), one-time secret sharing (secretshare/F60), and the dynamic PKI
		// secret (pkisecret/F67). Each is auth-gated, tenant-scoped under RLS (AN-1),
		// idempotent (AN-5), and event-sourced (AN-2); values are never logged or
		// returned beyond their design (AN-8). The machine-login route (authmethod/F58)
		// is public because the presented credential authenticates the workload; it is
		// still in the registry so OpenAPI/generated clients see the served contract.
		{method: "POST", path: "/api/v1/secrets/store", opID: "createSecret", summary: "Create an application secret (sealed at rest)", handler: a.createSecret, reqSchema: "SecretRequest", resSchema: "SecretMeta", successCode: "201", mutation: true, perm: authz.SecretsWrite},
		{method: "GET", path: "/api/v1/secrets/store", opID: "listSecrets", summary: "List application secret names (no values)", handler: a.listSecrets, query: page, resSchema: "SecretMetaList", successCode: "200", perm: authz.SecretsRead},
		{method: "POST", path: "/api/v1/secrets/store/import", opID: "importSecrets", summary: "Import a tree of application secrets (sealed at rest)", handler: a.importSecrets, reqSchema: "SecretImportRequest", resSchema: "SecretMetaList", successCode: "201", mutation: true, perm: authz.SecretsWrite},
		{method: "GET", path: "/api/v1/secrets/store/history/{name...}", opID: "getSecretVersion", summary: "Read one historical application-secret version", handler: a.getSecretVersion, pathParams: secretNamePath, query: []param{{name: "version", typ: "integer", desc: "historical version number to read"}}, resSchema: "SecretValue", successCode: "200", sensitiveResponse: true, perm: authz.SecretsRead},
		{method: "POST", path: "/api/v1/secrets/store/recover/{name...}", opID: "recoverSecretAt", summary: "Recover an application secret to a point in time", handler: a.recoverSecretAt, pathParams: secretNamePath, reqSchema: "SecretRecoverRequest", resSchema: "SecretMeta", successCode: "200", mutation: true, perm: authz.SecretsWrite},
		{method: "POST", path: "/api/v1/secrets/rotations", opID: "rotateStaticSecret", summary: "Run a rollback-safe static secret rotation", handler: a.rotateStaticSecret, reqSchema: "SecretRotationRequest", resSchema: "SecretRotation", successCode: "200", mutation: true, perm: authz.SecretsWrite},
		{method: "GET", path: "/api/v1/secrets/kubernetes-operator", opID: "getKubernetesSecretOperator", summary: "Report Kubernetes SecretSync operator coverage", handler: a.kubernetesSecretOperator, resSchema: "KubernetesSecretOperator", successCode: "200", perm: authz.SecretsRead},
		{method: "GET", path: "/api/v1/secrets/syncs/targets", opID: "listSecretSyncTargets", summary: "List built-in and configured secret-sync targets", handler: a.secretSyncTargets, resSchema: "SecretSyncTargetCatalog", successCode: "200", perm: authz.SecretsRead},
		{method: "POST", path: "/api/v1/secrets/syncs", opID: "syncSecret", summary: "Push a stored secret to a configured external sync target", handler: a.syncSecret, reqSchema: "SecretSyncRequest", resSchema: "SecretSync", successCode: "200", mutation: true, perm: authz.SecretsWrite},
		{method: "GET", path: "/api/v1/secrets/scans/repositories", opID: "getSecretRepositoryScanning", summary: "Report real-time repository secret-scanning posture", handler: a.secretRepoScanPosture, resSchema: "SecretRepositoryScanPosture", successCode: "200", perm: authz.SecretsRead},
		{method: "POST", path: "/api/v1/secrets/scans/repositories/{provider}/webhook", opID: "receiveSecretRepositoryWebhook", summary: "Queue a normalized provider repository secret scan", handler: a.receiveSecretRepoWebhook, pathParams: []param{{name: "provider", typ: "string", desc: "github, gitlab, or bitbucket"}}, reqSchema: "SecretRepositoryWebhookRequest", resSchema: "SecretRepositoryWebhookReceipt", successCode: "202", mutation: true, perm: authz.SecretsWrite},
		{method: "GET", path: "/api/v1/secrets/scans/third-party", opID: "getThirdPartySecretScanning", summary: "Report CI/CD, registry, Slack, and Jira secret-scanning posture", handler: a.thirdPartySecretScanPosture, resSchema: "ThirdPartySecretScanPosture", successCode: "200", perm: authz.SecretsRead},
		{method: "POST", path: "/api/v1/secrets/scans/third-party/{provider}/ingest", opID: "ingestThirdPartySecretScan", summary: "Queue a third-party artifact secret scan", handler: a.ingestThirdPartySecretScan, pathParams: []param{{name: "provider", typ: "string", desc: "cicd_log, container_registry, slack, or jira"}}, reqSchema: "ThirdPartySecretScanIngestRequest", resSchema: "ThirdPartySecretScanReceipt", successCode: "202", mutation: true, perm: authz.SecretsWrite},
		{method: "POST", path: "/api/v1/secrets/scans", opID: "scanSecrets", summary: "Run a Gitleaks secret scan and record redacted findings", handler: a.scanSecrets, reqSchema: "SecretScanRequest", resSchema: "SecretScan", successCode: "201", mutation: true, perm: authz.SecretsWrite},
		{method: "POST", path: "/api/v1/secrets/store/approvals/{name...}", opID: "approveSecretChange", summary: "Approve a pending sensitive secret-store change", handler: a.approveSecretChange, pathParams: secretNamePath, reqSchema: "SecretApprovalRequest", resSchema: "SecretApproval", successCode: "200", mutation: true, perm: authz.SecretsWrite},
		{method: "GET", path: "/api/v1/secrets/store/{name...}", opID: "getSecret", summary: "Read an application secret value", handler: a.getSecret, pathParams: secretNamePath, query: []param{{name: "resolve", typ: "boolean", desc: "expand ${secret.path} references in the returned value"}}, resSchema: "SecretValue", successCode: "200", sensitiveResponse: true, perm: authz.SecretsRead},
		{method: "PUT", path: "/api/v1/secrets/store/{name...}", opID: "rotateSecret", summary: "Rotate an application secret (new value, bumped version)", handler: a.rotateSecret, pathParams: secretNamePath, reqSchema: "SecretRequest", resSchema: "SecretMeta", successCode: "200", mutation: true, perm: authz.SecretsWrite},
		{method: "DELETE", path: "/api/v1/secrets/store/{name...}", opID: "deleteSecret", summary: "Delete an application secret", handler: a.deleteSecret, pathParams: secretNamePath, successCode: "204", mutation: true, perm: authz.SecretsWrite},
		{method: "POST", path: "/api/v1/secrets/leases", opID: "issueDynamicSecretLease", summary: "Issue a dynamic secret lease", handler: a.issueDynamicLease, reqSchema: "DynamicLeaseRequest", resSchema: "DynamicLease", successCode: "201", mutation: true, sensitiveResponse: true, perm: authz.SecretsWrite},
		{method: "GET", path: "/api/v1/secrets/leases/{lease_id}", opID: "getDynamicSecretLease", summary: "Read dynamic secret lease metadata", handler: a.getDynamicLease, pathParams: dynamicLeaseIDPath, resSchema: "DynamicLease", successCode: "200", perm: authz.SecretsRead},
		{method: "POST", path: "/api/v1/secrets/leases/{lease_id}/renew", opID: "renewDynamicSecretLease", summary: "Renew a dynamic secret lease", handler: a.renewDynamicLease, pathParams: dynamicLeaseIDPath, reqSchema: "DynamicLeaseRenewRequest", resSchema: "DynamicLease", successCode: "200", mutation: true, perm: authz.SecretsWrite},
		{method: "POST", path: "/api/v1/secrets/leases/{lease_id}/revoke", opID: "revokeDynamicSecretLease", summary: "Revoke a dynamic secret lease", handler: a.revokeDynamicLease, pathParams: dynamicLeaseIDPath, resSchema: "DynamicLease", successCode: "200", mutation: true, perm: authz.SecretsWrite},

		{method: "POST", path: "/api/v1/secrets/shares", opID: "createShare", summary: "Create a one-time secret share (returns a bearer token)", handler: a.createShare, reqSchema: "ShareRequest", resSchema: "ShareToken", successCode: "201", mutation: true, sensitiveResponse: true, perm: authz.SecretsWrite},
		{method: "POST", path: "/api/v1/secrets/shares/redeem", opID: "redeemShare", summary: "Redeem a one-time secret share exactly once", handler: a.redeemShare, reqSchema: "ShareRedeemRequest", resSchema: "ShareValue", successCode: "200", mutation: true, sensitiveResponse: true, perm: authz.SecretsRead},

		{method: "POST", path: "/api/v1/secrets/pki", opID: "issuePKISecret", summary: "Issue a dynamic PKI secret (short-lived cert + key)", handler: a.issuePKISecret, reqSchema: "PKISecretRequest", resSchema: "PKISecret", successCode: "201", mutation: true, sensitiveResponse: true, perm: authz.SecretsWrite},
		{method: "POST", path: "/api/v1/secrets/login", opID: "machineLogin", summary: "Exchange a machine credential for a scoped workload session", handler: a.machineLogin, reqSchema: "MachineLoginRequest", resSchema: "MachineLoginResponse", successCode: "200", sensitiveResponse: true},

		// Transit/EaaS (KMS-01/F66): a served envelope-free cryptographic operation
		// surface backed by compile-time Go interfaces behind internal/crypto. This
		// deliberately keeps the prior-art shape of crypto.Signer / JCA / OpenSSL
		// ENGINE adapter boundaries, and does not introduce runtime crypto suite
		// registration, DLL/plugin engines, or a policy controller that feeds provider
		// behavior at runtime.
		{method: "POST", path: "/api/v1/transit/keys", opID: "createTransitKey", summary: "Create a tenant-scoped transit key", handler: a.createTransitKey, reqSchema: "TransitKeyRequest", resSchema: "TransitKey", successCode: "201", mutation: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/transit/keys/rotate", opID: "rotateTransitKey", summary: "Rotate a tenant-scoped transit key", handler: a.rotateTransitKey, reqSchema: "TransitRotateRequest", resSchema: "TransitKey", successCode: "200", mutation: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/transit/encrypt", opID: "encryptTransit", summary: "Encrypt plaintext with a transit key", handler: a.encryptTransit, reqSchema: "TransitEncryptRequest", resSchema: "TransitCiphertext", successCode: "200", mutation: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/transit/decrypt", opID: "decryptTransit", summary: "Decrypt transit ciphertext", handler: a.decryptTransit, reqSchema: "TransitDecryptRequest", resSchema: "TransitPlaintext", successCode: "200", sensitiveResponse: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/transit/rewrap", opID: "rewrapTransit", summary: "Re-encrypt transit ciphertext under the current key version", handler: a.rewrapTransit, reqSchema: "TransitRewrapRequest", resSchema: "TransitCiphertext", successCode: "200", mutation: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/transit/hmac", opID: "hmacTransit", summary: "Compute an HMAC with a transit key", handler: a.hmacTransit, reqSchema: "TransitHMACRequest", resSchema: "TransitHMAC", successCode: "200", mutation: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/transit/sign", opID: "signTransit", summary: "Sign a message with a transit signing key", handler: a.signTransit, reqSchema: "TransitSignRequest", resSchema: "TransitSignature", successCode: "200", mutation: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/transit/verify", opID: "verifyTransit", summary: "Verify a transit signature", handler: a.verifyTransit, reqSchema: "TransitVerifyRequest", resSchema: "TransitVerify", successCode: "200", perm: authz.KeysRead},

		// Code-signing (CLM-06/F50): key-backed and keyless/Sigstore artifact signing
		// over the served path. Requests carry only a digest and key/identity
		// references; the authenticated principal is the signer identity. The service
		// queues transparency-log publication through outbox (AN-6), rather than
		// calling Rekor/Fulcio inline.
		{method: "POST", path: "/api/v1/code-signing/sign", opID: "signCodeArtifact", summary: "Sign an artifact digest with a managed code-signing key", handler: a.signCodeArtifact, reqSchema: "CodeSigningRequest", resSchema: "CodeSigningSignature", successCode: "200", mutation: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/code-signing/keyless", opID: "signCodeArtifactKeyless", summary: "Sign an artifact digest with a verified Sigstore/Fulcio identity", handler: a.signCodeArtifactKeyless, reqSchema: "CodeSigningKeylessRequest", resSchema: "CodeSigningSignature", successCode: "200", mutation: true, perm: authz.KeysWrite},

		// Managed-key (BYOK/HSM) lifecycle (CRYPTO-005 / EXC-CRYPTO-01). The private
		// material lives in the KMS/HSM and never enters this process. Generate mints
		// new material (no prior approval); rotate/revoke/zeroize are destructive and
		// require a distinct-approver approval (dual control) enforced by the service.
		// All four are idempotent (AN-5) and event-sourced (AN-2).
		{method: "POST", path: "/api/v1/managed-keys", opID: "generateManagedKey", summary: "Generate a BYOK/HSM-resident managed key (private material stays in the provider)", handler: a.generateManagedKey, reqSchema: "ManagedKeyGenerateRequest", resSchema: "ManagedKey", successCode: "201", mutation: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/managed-keys/rotate", opID: "rotateManagedKey", summary: "Rotate a managed key (mint a successor; requires dual-control approval)", handler: a.rotateManagedKey, reqSchema: "ManagedKeyActionRequest", resSchema: "ManagedKey", successCode: "200", mutation: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/managed-keys/revoke", opID: "revokeManagedKey", summary: "Revoke a managed key at the provider (requires dual-control approval)", handler: a.revokeManagedKey, reqSchema: "ManagedKeyActionRequest", resSchema: "ManagedKey", successCode: "200", mutation: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/managed-keys/zeroize", opID: "zeroizeManagedKey", summary: "Zeroize a managed key's material at the provider (requires dual-control approval)", handler: a.zeroizeManagedKey, reqSchema: "ManagedKeyActionRequest", resSchema: "ManagedKey", successCode: "200", mutation: true, perm: authz.KeysWrite},

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
// Bearer trstctl API token authenticates by its hash (carrying its own tenant
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
			return a.sessionPrincipal(r.Context(), sess), nil
		}
	}
	return authz.Principal{}, errors.New("api: unauthenticated")
}

// sessionPrincipal builds the RBAC principal for a verified OIDC session: the
// session's role names resolve (against the role registry) to grants held
// tenant-wide within the session's tenant. This is what makes a browser login
// authorize API calls, not just /auth/me.
func (a *API) sessionPrincipal(ctx context.Context, sess auth.Session) authz.Principal {
	roleNames := a.sessionRoleNames(ctx, sess)
	grants := make([]authz.Grant, 0, len(roleNames))
	for _, name := range roleNames {
		if role, ok := a.roles.Role(name); ok {
			grants = append(grants, authz.Grant{Role: role, Scope: authz.Scope{TenantID: sess.TenantID}})
		}
	}
	return authz.Principal{TenantID: sess.TenantID, Subject: sess.Subject, Grants: grants}
}

func (a *API) sessionRoleNames(ctx context.Context, sess auth.Session) []string {
	roleNames := append([]string(nil), sess.Roles...)
	if a.store != nil && sess.TenantID != "" && sess.Subject != "" {
		if member, err := a.store.GetTenantMember(ctx, sess.TenantID, sess.Subject); err == nil {
			if member.Status == "offboarded" {
				roleNames = nil
			} else {
				roleNames = mergeRoleNames(roleNames, member.Roles)
			}
		}
	}
	return roleNames
}

func mergeRoleNames(base, extra []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(base)+len(extra))
	for _, role := range append(append([]string(nil), base...), extra...) {
		role = strings.TrimSpace(role)
		if role == "" || seen[role] {
			continue
		}
		seen[role] = true
		out = append(out, role)
	}
	return out
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	if tok := strings.TrimSpace(r.Header.Get("X-Vault-Token")); tok != "" {
		return tok
	}
	return ""
}

// guard enforces the route's required permission (AN: RBAC/F8) before invoking
// the handler. A route with no permission ("") is public. Denials are
// problem+json: 401 when the principal can't be resolved, 403 when the principal
// lacks the permission in the route target scope.
func (a *API) guard(perm authz.Permission, scope routeScope, h http.HandlerFunc) http.HandlerFunc {
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
		target, err := requestTargetScope(principal, r, scope)
		if err != nil {
			a.writeError(w, err)
			return
		}
		if !principal.Can(perm, target) {
			a.writeProblem(w, problem.New(http.StatusForbidden, "forbidden: requires "+string(perm)))
			return
		}
		if err := a.checkABAC(r.Context(), r, principal, perm, target); err != nil {
			a.writeError(w, err)
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

func requestTargetScope(principal authz.Principal, r *http.Request, scope routeScope) (authz.Scope, error) {
	target := authz.Scope{TenantID: principal.TenantID, Project: r.Header.Get("X-Project")}
	if scope == nil {
		return target, nil
	}
	scoped, err := scope(r)
	if err != nil {
		return authz.Scope{}, err
	}
	if scoped.TenantID != "" && scoped.TenantID != principal.TenantID {
		return authz.Scope{}, errStatus(http.StatusForbidden, "forbidden: cross-tenant scope")
	}
	if scoped.Project != "" {
		target.Project = scoped.Project
	}
	if scoped.Profile != "" {
		target.Profile = scoped.Profile
	}
	if scoped.Issuer != "" {
		target.Issuer = scoped.Issuer
	}
	return target, nil
}

func (a *API) checkABAC(ctx context.Context, r *http.Request, principal authz.Principal, perm authz.Permission, target authz.Scope) error {
	if a.abac == nil {
		return nil
	}
	now := time.Now().UTC()
	if a.abacNow != nil {
		now = a.abacNow().UTC()
	}
	resource := map[string]string{
		"request.method": r.Method,
		"request.path":   r.URL.Path,
	}
	if target.Project != "" {
		resource["request.project"] = target.Project
		resource["project"] = target.Project
	}
	if target.Profile != "" {
		resource["request.profile"] = target.Profile
		resource["profile"] = target.Profile
	}
	if target.Issuer != "" {
		resource["request.issuer"] = target.Issuer
		resource["issuer"] = target.Issuer
	}
	in := policy.ABACInput{
		Permission: string(perm),
		TenantID:   principal.TenantID,
		Actor:      principal.Subject,
		ActorAttrs: map[string]string{
			"subject": principal.Subject,
			"roles":   strings.Join(principalRoles(principal), ","),
		},
		Resource:   resource,
		Env:        copyStringMap(a.abacEnvironment),
		Now:        now.Format(time.RFC3339),
		NowUnix:    now.Unix(),
		NowHourUTC: now.Hour(),
		NowWeekday: now.Weekday().String(),
	}
	d, err := a.abac.EvaluateDeny(ctx, in)
	switch {
	case errors.Is(err, bulkhead.ErrRejected):
		return errStatus(http.StatusServiceUnavailable, "ABAC engine busy; retry")
	case err != nil:
		return errStatus(http.StatusForbidden, "denied by ABAC (evaluation error)")
	case d.Deny:
		reason := d.Reason
		if reason == "" {
			reason = "denied by ABAC"
		}
		return errStatus(http.StatusForbidden, "denied by ABAC: "+reason)
	default:
		return nil
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

type secretResponse interface {
	wipeSecrets()
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
			if sr, ok := body.(secretResponse); ok {
				defer sr.wipeSecrets()
			}
			bj, mErr := json.Marshal(body)
			if mErr != nil {
				return nil, mErr
			}
			defer secret.Wipe(bj)
			bodyJSON = bj
		}
		return json.Marshal(cachedResponse{Status: status, Body: bodyJSON})
	})
	if err != nil {
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(raw)

	var c cachedResponse
	if err := json.Unmarshal(raw, &c); err != nil {
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(c.Body)
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
	case a.writeExternalCAError(w, err):
	case a.writeCAHierarchyError(w, err):
	case a.writeAttestedIssuanceError(w, err):
	case a.writeBrokerError(w, err):
	case a.writeEphemeralError(w, err):
	case a.writePAMError(w, err):
	case a.writeSSHWorkflowError(w, err):
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
	defer secret.Wipe(b)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func (a *API) notFound(w http.ResponseWriter, _ *http.Request) {
	a.writeProblem(w, problem.New(http.StatusNotFound, "no such resource"))
}

func errWithStatus(status int, err error) *apiError {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae
	}
	return errStatus(status, err.Error())
}

func decodeJSON(r *http.Request, v any) error {
	return decodeJSONWithLimit(r, v, defaultRESTJSONBodyLimit)
}

func decodeJSONWithLimit(r *http.Request, v any, limit int64) error {
	if r.Body == nil {
		return errStatus(http.StatusBadRequest, "request body is required")
	}
	if limit <= 0 {
		limit = defaultRESTJSONBodyLimit
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return errStatus(http.StatusBadRequest, "invalid JSON body: "+err.Error())
	}
	defer secret.Wipe(body)
	if int64(len(body)) > limit {
		return errStatus(http.StatusRequestEntityTooLarge, fmt.Sprintf("JSON request body too large; maximum is %d bytes", limit))
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(v); err != nil {
		return errStatus(http.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", err))
	}
	var extra json.RawMessage
	err = dec.Decode(&extra)
	if err == nil {
		return errStatus(http.StatusBadRequest, "invalid JSON body: multiple JSON values are not allowed")
	}
	if !errors.Is(err, io.EOF) {
		return errStatus(http.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", err))
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
