// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/orchestrator"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

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

// LicensedRoute lets proprietary edition packages mount their own guarded API
// routes without making the MPL core import ee/. The route metadata is still fed
// through the shared OpenAPI/RBAC/idempotency machinery.
type LicensedRoute struct {
	Method            string
	Path              string
	OperationID       string
	Summary           string
	Handler           func(*API) http.HandlerFunc
	PathParams        []RouteParam
	Query             []RouteParam
	RequestSchema     string
	RequestOptional   bool
	ResponseSchema    string
	SuccessCode       string
	Mutation          bool
	SensitiveResponse bool
	Permission        authz.Permission
}

// RouteParam is the exported form of the small OpenAPI parameter descriptor used
// by licensed route metadata.
type RouteParam struct {
	Name        string
	Type        string
	Format      string
	Description string
}

// PathStringParam describes a string path parameter for a licensed route.
func PathStringParam(name, desc string) RouteParam {
	return RouteParam{Name: name, Type: "string", Description: desc}
}

// WithLicensedRoutes appends proprietary edition routes to this API instance.
func WithLicensedRoutes(routes ...LicensedRoute) Option {
	return func(c *config) { c.licensedRoutes = append(c.licensedRoutes, routes...) }
}

// WithLicensedSchemas appends proprietary edition OpenAPI component schemas to
// this API instance. Names must be unique across core and licensed components.
func WithLicensedSchemas(schemas map[string]*Schema) Option {
	return func(c *config) {
		if len(schemas) == 0 {
			return
		}
		if c.licensedSchemas == nil {
			c.licensedSchemas = map[string]*Schema{}
		}
		for name, schema := range schemas {
			c.licensedSchemas[name] = schema
		}
	}
}

// WithLicense wires the offline license manager that backs GET /v1/editions.
// nil keeps the default Community posture.
func WithLicense(m *license.Manager) Option {
	return func(c *config) { c.license = m }
}

// WithRemediation mounts the Enterprise remediation HTTP surface. Without it the
// route registry still describes the full licensed API contract, but the runtime
// mux returns 404 for incident and licensed remediation paths so Community cannot probe a
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

// WithServiceNowBindings wires the operator-approved ServiceNow destinations and
// credential references. The served ITSM route fails closed unless a request matches
// one of these bindings exactly after URL normalization.
func WithServiceNowBindings(bindings ...ServiceNowBinding) Option {
	return func(c *config) { c.serviceNowBindings = append([]ServiceNowBinding(nil), bindings...) }
}

// WithOutboundEnvCredentialRefs wires the operator-approved env-backed credential
// references that API-authored outbound integrations may use. ServiceNow uses the
// stricter endpoint+token binding above; this allowlist covers generic discovery
// and response-integration refs before they can reach the outbox worker.
func WithOutboundEnvCredentialRefs(refs ...string) Option {
	return func(c *config) {
		c.outboundEnvCredentialRefs = normalizeOutboundEnvCredentialRefs(refs)
	}
}

// WithACMEDNS01Providers appends signed, served DNS-provider plugins to the
// built-in ACME DNS-01 provider catalog and provider-config admission allowlist.
func WithACMEDNS01Providers(items ...ACMEDNS01ProviderCatalogItem) Option {
	return func(c *config) {
		c.acmeDNS01Providers = append(c.acmeDNS01Providers, items...)
	}
}

// WithACMEDNS01CAAResolver wires the authoritative live CAA resolver used by
// DNS-01 preflight. Production passes acme.DefaultCAAResolver; tests pass a
// deterministic resolver.
func WithACMEDNS01CAAResolver(resolver acmesrv.CAAResolver) Option {
	return func(c *config) { c.acmeCAAResolver = resolver }
}
