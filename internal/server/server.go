// Package server is the composition root of the trstctl control plane (S7.7): it
// wires the configuration, datastore, event log, projections, orchestrator, and
// REST API into one serving process, provisions an issuing CA whose key lives in
// the out-of-process signer (AN-4), and shuts everything down in order. It is the
// integration seam — it introduces no new product capability, only the assembly
// of capabilities that already exist and are tested as packages.
package server

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"trstctl.com/trstctl/internal/agent/enroll"
	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authmethod"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/pqc"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/idemgc"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/lifecycle"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/outboxgc"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/protocols/ari"
	sshca "trstctl.com/trstctl/internal/protocols/ssh"
	"trstctl.com/trstctl/internal/rotation"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/telemetry"
	transitpkg "trstctl.com/trstctl/internal/transit"
	"trstctl.com/trstctl/internal/webui"
)

// SignerProvider yields the current connected signer client, or nil when no
// signer is healthy. The signing.Supervisor satisfies it.
type SignerProvider interface {
	Client() *signing.Client
}

// FederationWorker is the core-owned runtime contract for cross-cluster import
// workers. The implementation lives in ee/federation; core only starts, stops,
// and closes the worker when the licensed attach seam supplies one.
type FederationWorker interface {
	Run(context.Context) error
	Close() error
}

// FederationCheckpointStore is the core checkpoint seam federation consumes.
// store.Store implements it, but the worker construction remains outside core.
type FederationCheckpointStore interface {
	EnsureFederationCheckpoint(ctx context.Context, peerID string) error
	FederationCheckpoint(ctx context.Context, peerID string) (uint64, error)
	AdvanceFederationCheckpoint(ctx context.Context, peerID string, seq uint64) error
}

// FederationFactory constructs the licensed federation worker from the server
// spine. Nil means no Enterprise HA/federation worker is mounted.
type FederationFactory func(context.Context, *events.Log, *projections.Projector, FederationCheckpointStore, *slog.Logger) (FederationWorker, error)

// Deps are the wired dependencies of the serving control plane. Tests inject an
// embedded store/log and an in-process signer; production wires the real ones.
type Deps struct {
	Store             *store.Store
	Log               *events.Log
	Signer            SignerProvider            // may be nil → issuance is unavailable (fail closed)
	SignAuthorizer    *crypto.SignAuthorizer    // test/eval token provider; production should use SignTokenProvider
	SignTokenProvider signing.SignTokenProvider // independent approval-token source for dual-control signer handles
	// ManagedKeyFactory is supplied only by the tagged EE attach seam when the
	// Enterprise BYOK feature is licensed and configured. Nil leaves the
	// /api/v1/managed-keys/* surface unmounted, so Community receives 404.
	ManagedKeyFactory ManagedKeyServiceFactory
	// KMIPFactory is supplied only by the tagged EE attach seam when the Enterprise
	// BYOK feature is licensed. Nil leaves the KMIP listener unmounted even if KMIP
	// config is present.
	KMIPFactory KMIPFactory
	// CodeSigning enables the served code-signing surface (CLM-06/F50): key-backed
	// artifact signing through a compile-time key resolver (PKCS#11/HSM when supplied,
	// software keys otherwise), keyless/Sigstore signing through configured Fulcio-style
	// attestors, and Rekor transparency-log publication through outbox.
	CodeSigning CodeSigningConfig
	EgressGuard *egress.Guard
	// FederationFactory is supplied only by the tagged EE attach seam when the
	// Enterprise HA-support feature is licensed. Leader election, projection
	// checkpoints, and advisory locks remain core and free.
	FederationFactory FederationFactory
	// GovernanceFactory is supplied only by the tagged EE attach seam when the
	// Enterprise governance feature is licensed. Nil keeps compliance evidence
	// routes unmounted; audit/privacy mechanisms stay core.
	GovernanceFactory GovernanceFactory
	// TelemetryReporter is the opt-in usage reporter (COMP-04). Nil means telemetry
	// is off; Run only wires it when telemetry.enabled is explicitly true, and the
	// reporter payload is fixed to anonymized, bucketed, non-PII fields.
	TelemetryReporter *telemetry.Reporter
	OutboxHandler     orchestrator.Handler // delivers outbox entries; defaults to a no-op success
	APIOptions        []api.Option         // auth/audit/etc.
	License           *license.Manager     // offline edition state exposed by GET /v1/editions
	EnableRemediation bool                 // Enterprise remediation: incident execution + PQC migration routes
	SignTimeout       time.Duration        // per-issuance signer deadline (slow → fail closed)
	CACommonName      string
	CACertFile        string             // persisted issuing-CA cert path; reused across restarts so the CA is stable (R3.2)
	LeafProfile       crypto.LeafProfile // served-leaf RFC 5280/BR profile: CDP/AIA/policy + constraints (PKIGOV-001/002)
	DefaultProfile    string             // certificate-profile name enforced on the served mint when it resolves (PKIGOV-002); empty = none
	// PolicyModule is the OPA/Rego policy document gating the served issue/deploy/
	// revoke path (EXC-WIRE-03). Empty uses policy.BaseModule (default-deny, permit
	// revoke, require a bound profile to issue/deploy). The engine is fail-closed,
	// audited (AN-2), and runs on the policy bulkhead (AN-7). Set EnablePolicyGate to
	// turn enforcement on; with it off the served path keeps the prior behavior.
	PolicyModule string
	// EnablePolicyGate turns on the served default-deny policy gate. When true, every
	// served issue/deploy/revoke transition is denied unless the policy explicitly
	// allows it (fail closed). Off (the zero value) preserves the prior served
	// behavior so an upgrade does not silently start denying.
	EnablePolicyGate bool
	// ABACModule is a deny-only OPA/Rego overlay (package trstctl.abac) layered over
	// RBAC and the primary policy gate. It may inspect input.env, input.now_*,
	// input.actor_attrs, and resource metadata such as input.resource.env. It can
	// only deny; it never grants access beyond RBAC. EnableABAC compiles and wires it
	// fail-closed.
	ABACModule string
	// EnableABAC turns on the ABAC deny overlay. Invalid Rego or evaluator errors
	// deny rather than silently allowing. Off preserves prior RBAC/policy behavior.
	EnableABAC bool
	// ABACEnvironment is copied into input.env for every ABAC evaluation.
	ABACEnvironment map[string]string
	// BreakglassCACertDER and BreakglassPublicKeyDER pin the recovery-side verifier
	// material for the served break-glass reconciliation endpoint. The route accepts
	// only signed offline bundles; it never trusts verifier material supplied by the
	// caller and never performs online emergency issuance.
	BreakglassCACertDER    []byte
	BreakglassPublicKeyDER []byte
	// RequireApproval turns on served dual-control for privileged transitions (issue
	// and revoke): the transition is denied unless a DISTINCT approver has recorded an
	// approval (the served half of RED-004 / SEC-002). Backed by the store's issuance
	// approval tables under RLS (AN-1). Off (the zero value) keeps the prior behavior.
	RequireApproval bool
	// RequiredApprovals is the number of distinct approvals a privileged action needs
	// when RequireApproval is on. Zero defaults to 2 (dual control), matching
	// internal/approval.
	RequiredApprovals int
	AuditSigningKey   *jose.SigningKey // persistent audit export key; when set, wires the audit endpoints (R2.1)
	// ComplianceSigner signs served framework evidence-pack exports (COMP-01).
	// Nil generates a process-local locked ECDSA key when audit + store are wired.
	ComplianceSigner crypto.DigestSigner
	AuditRetention   time.Duration // audit retention window (R4.4); >0 with AuditArchiveDir enables the retention worker
	AuditArchiveDir  string        // cold-storage directory for signed audit archive bundles (R4.4)
	// PrivacyRetention enables the non-audit PII retention worker (PRIVACY-003).
	// It emits privacy.retention.enforced events and projects pseudonymization from
	// the event's cutoffs, so operational retention remains replayable (AN-2).
	PrivacyRetentionEnabled  bool
	PrivacyRetentionInterval time.Duration
	PrivacyRetentionPolicy   privacy.RetentionPolicy
	GovernancePolicySource   privacy.RetentionPolicySource
	// IdempotencyRetention bounds how long a completed idempotency key is kept
	// before the background GC sweep reclaims it (SPINE-002). Zero uses
	// idemgc.DefaultRetention. AN-5 holds within the window.
	IdempotencyRetention time.Duration
	// OutboxRetention bounds how long a delivered outbox row is kept before the
	// background purge sweep reclaims it (SPINE-003). Zero uses
	// outboxgc.DefaultRetention. At-least-once delivery (AN-6) is unaffected — only
	// already-delivered rows are reclaimed.
	OutboxRetention time.Duration
	// OutboxDeliveryTimeout is the per-message deadline for generic outbox
	// deliveries. Zero uses the orchestrator default. Timed-out rows are retried via
	// the normal outbox backoff/dead-letter path, and the served binary records a
	// timeout metric labeled by tenant and destination.
	OutboxDeliveryTimeout time.Duration
	// LifecycleRenewBefore enables the leader-only lifecycle scheduler. When >0, the
	// scheduler scans deployed X.509 identities and queues the existing ca.renew
	// outbox path for certificates expiring inside this window. Zero disables the
	// scheduler (tests can still drive manual renewal transitions).
	LifecycleRenewBefore time.Duration
	// LifecycleAlertBefore enables expiry alert sweeps for served notification
	// channels. When >0 and NotificationChannels is non-empty, the leader scheduler
	// finds active X.509 certificates expiring inside this window, enqueues a
	// notification.expiry outbox row, and stamps alerted_at in the same transaction.
	// The outbox worker then dispatches the alert through the configured notify
	// channels (Slack, Teams, email, PagerDuty, OpsGenie, webhook). Zero disables
	// expiry-alert sweeps.
	LifecycleAlertBefore time.Duration
	// LifecycleInterval is the scheduler cadence. Zero selects a conservative default.
	LifecycleInterval time.Duration
	// NotificationChannels are the operator-configured served notification sinks
	// (NOTIF-01/F29). They are driven only by notification.* outbox rows; the
	// scheduler never calls a channel directly, preserving AN-6 at-least-once delivery.
	NotificationChannels []notify.Notifier
	Logger               *slog.Logger    // structured access log sink (R2.2); nil discards
	TraceExporter        observ.Exporter // completed-span sink (R2.2); nil is a no-op
	OTLPExporter         *observ.OTLPExporter
	Bulkhead             *bulkhead.Set   // per-subsystem bounded pools (R2.3/AN-7); nil uses bulkhead.Default()
	RateLimiter          api.RateLimiter // per-tenant rate limiter (R2.3); nil disables rate limiting
	// SecurityHeaders configures the web-hardening response headers + CORS policy
	// applied to the whole served surface (SEC-003/WIRE-005). The zero value is
	// safe (headers on, HSTS off, same-origin-only CORS); Run sets TLS from the
	// server's TLS mode and AllowedOrigins from config.
	SecurityHeaders SecurityHeaders

	// Protocols enables/configures the served issuance-protocol endpoints
	// (EXC-WIRE-02): ACME, EST, SCEP, CMP (mounted on the TLS mux) and the SPIFFE
	// Workload API + SSH CA. Each enabled protocol mints through the signer-backed,
	// tenant-scoped, event-sourced, idempotent issuance seam — the running binary
	// then speaks the RFC protocol to stock clients. The zero value serves none. Run
	// fills this from config.Protocols.
	Protocols config.Protocols
	// ProtocolTenant is the platform default tenant a protocol binds when its own
	// TenantID is unset. Run passes the configured default tenant.
	ProtocolTenant string
	// AttestedIssuance enables the served workload attestation → X.509-SVID mint
	// (NHI-02/F30). The running binary constructs an attest.Verifier from all six
	// attesters, verifies the presented proof, signs through the out-of-process
	// issuing CA, and records the SVID as certificate.recorded. The zero value leaves
	// the route fail-closed with 503.
	AttestedIssuance AttestedIssuanceConfig
	// AgentBroker enables the served AI-agent / NHI identity broker (NHI-03/F61).
	// The running binary composes internal/broker with the policy engine, attesters,
	// signer-backed short-lived X.509-SVID issuance, and event-sourced certificate
	// inventory so grants show in the credential graph. The zero value leaves the
	// route fail-closed with 503.
	AgentBroker AgentBrokerConfig
	// EphemeralIssuance enables the served approval-gated JIT credential path
	// (NHI-04/F25/F33). A request must pass attestation, open/meet dual-control
	// approval, and then mint through the signer-backed CA. The zero value leaves
	// the route fail-closed with 503.
	EphemeralIssuance EphemeralIssuanceConfig
	// PAM enables the served JIT privileged-access broker (PAM-01/F33): attested
	// requests receive short-lived Postgres roles or SSH user certificates, and a
	// leader worker records automatic expiry. The zero value leaves the route
	// fail-closed with 503.
	PAM PAMConfig

	// ExternalCAs configures the served upstream-CA registry (CLM-03/F4): each entry
	// is a built-in CA plugin instance (Let's Encrypt/ACME, DigiCert, Sectigo, AD CS,
	// AWS PCA, GCP CAS, EJBCA, smallstep, ...), and the running binary exposes it
	// under /api/v1/external-cas. Upstream credentials live in these process
	// configs/plugins as []byte where secret, never in tenant JSON. Empty leaves the
	// surface fail-closed.
	ExternalCAs []ExternalCA

	// ConnectorRegistry configures the trusted, in-process native deployment
	// connectors (CLM-05/F7/F27). When set, connector.deploy outbox rows whose
	// connector name is registered here are delivered by the running binary through
	// the connector SDK sandbox and recorded as event-sourced delivery receipts.
	// Empty preserves the prior behavior: plugin-owned rows may run through the
	// signed WASM plugin surface; otherwise they are acknowledged as unrouted.
	ConnectorRegistry *connector.Registry

	// Plugins configures the served WASM-plugin surface (EXC-WIRE-05, closing
	// ARCH-007/SUPPLY-004): the directory of operator-supplied connector plugins, the
	// trusted Ed25519 keys that admit a signed module, optional content-digest pins,
	// and the capability grant they run under. The zero value leaves the surface OFF
	// (a connector.deploy is acknowledged unrouted, as before). When configured, Build
	// loads and PROVENANCE-VERIFIES every plugin at startup — an unsigned, wrong-key,
	// tampered, or unpinned module makes Build fail closed, so the binary never serves
	// an unverified plugin. Run fills this from config.Plugins.
	Plugins PluginConfig
	// ACMEValidators overrides the ACME domain-validation validators. Production
	// leaves it nil → the served ACME server uses acme.DefaultValidators() (real,
	// SSRF-guarded HTTP-01/DNS-01/TLS-ALPN-01, fail closed). It exists so the
	// end-to-end acceptance test can inject a loopback-capable validator that reaches
	// a test challenge server without weakening the production default.
	ACMEValidators *acme.Validators

	// OIDC configures the served browser SSO login + session + per-user → tenant
	// mapping (EXC-WIRE-01, closing SEC-001/WIRE-001/SURFACE-002/TENANT-004). When
	// OIDC.Enabled, Build wires api.WithAuth so the running binary serves /auth/login,
	// /auth/callback, /auth/me, /auth/logout and a session cookie authorizes API calls
	// under the SAME RBAC + RLS tenant scoping as an API token. Disabled (the zero
	// value) preserves the prior token-only behavior. An enabled-but-misconfigured
	// block makes Build fail closed. Run fills this from config.Auth.OIDC.
	OIDC config.OIDC
	// SAML configures the served SAML 2.0 SP login + session + per-user → tenant
	// mapping. Run fills this from config.Auth.SAML.
	SAML config.SAML
	// LDAP configures served LDAP / Active Directory username-password bind login
	// and group-to-role mapping. Run fills this from config.Auth.LDAP.
	LDAP config.LDAP
	// SCIM configures served SCIM 2.0 provisioning under /scim/v2. Run fills this
	// from config.Auth.SCIM.
	SCIM config.SCIM
	// AuthHTTPClient performs the OIDC code→token exchange. Production leaves it nil
	// (a default 10s client). The end-to-end acceptance test injects a client that can
	// reach a loopback mock IdP, without weakening the production default.
	AuthHTTPClient *http.Client

	// EnableSecretsAPI turns on the served secrets/identity surface (GAP-006): the
	// secret store (CRUD + rotation, secretsdk/F64), one-time secret sharing
	// (secretshare/F60), the dynamic PKI secret (pkisecret/F67), and machine login
	// (authmethod/F58) under /api/v1/secrets/*. Off by default (fail closed): an
	// upgrade does not silently expose a new secrets surface. When on, a KEK is
	// REQUIRED (envelope encryption at rest); Build fails closed without one. Every
	// route is auth-gated, tenant-scoped under RLS (AN-1), idempotent (AN-5), and
	// event-sourced (AN-2); values are never logged or returned beyond their design
	// (AN-8). Run fills this from config.Secrets.EnableAPI.
	EnableSecretsAPI bool
	// KEK is the credential key-encryption key (seal.KeyWrapper) the secret store seals
	// values under at rest (R3.1/AN-8). It also seals the SCEP/CMP RA transport
	// identity when those protocol endpoints are enabled. The rest of the platform
	// loads-and-destroys it transiently; these served surfaces need it retained for the
	// process lifetime, so Run passes a retained handle only when needed. Required when
	// EnableSecretsAPI, protocols.scep.enabled, or protocols.cmp.enabled is true. The
	// plaintext secret never touches the store — only the sealed blob does.
	KEK sealKeyWrapper
	// SecretsAuthSecret is the HMAC key the served machine-login token method
	// (authmethod.TokenMethod) verifies a workload token against (F58). It is []byte and
	// never logged (AN-8). When empty, the login route reports the method is not
	// configured (the secret store / share / pki sub-features still work). Run derives
	// it from a configured key file.
	SecretsAuthSecret []byte
	// MachineAuthMethods returns tenant-scoped workload login methods such as
	// Kubernetes SAT, AWS IAM, GCP, Azure, OIDC, and JWT. Empty keeps those methods
	// off while preserving the HMAC token method when SecretsAuthSecret is configured.
	MachineAuthMethods func(tenantID string) []authmethod.Method
	// DynamicSecretProviders are the configured dynamic-secret providers exposed by
	// /api/v1/secrets/leases (F65). Empty keeps the route fail-closed.
	DynamicSecretProviders []dynsecret.Provider
	// SecretRotators are the configured rollback-safe static secret rotators exposed
	// by /api/v1/secrets/rotations (F37). Empty keeps the route fail-closed.
	SecretRotators map[string]rotation.Rotator
	// SecretSyncTargets are the configured external secret-sync destinations exposed
	// by /api/v1/secrets/syncs (F68). Empty keeps the route fail-closed.
	SecretSyncTargets map[string]*secretsync.Target
	// SecretScanGitleaksBin points at the pinned Gitleaks binary used by
	// POST /api/v1/secrets/scans (SEC-07/F39). Empty resolves
	// TRSTCTL_GITLEAKS_BIN/tools/bin/gitleaks/PATH at request time.
	SecretScanGitleaksBin string
	// DynamicLeaseWorkerInterval controls the served dynamic leaseworker cadence.
	// Zero uses the production default.
	DynamicLeaseWorkerInterval time.Duration

	// EnableAISurface turns on the served AI / RCA / NL-query / MCP surface (SURFACE-003;
	// F75/F76/F77/F78) under /api/v1/ai/* and /api/v1/mcp/*. OFF by default (fail closed):
	// an upgrade does not silently expose an AI surface. MCP investigation stays
	// read-only unless EnableMCPWriteTools is also set. All calls are tenant-scoped
	// under RLS (the tenant is the authenticated principal's, never a request field —
	// AN-1), auth-gated, and rate-limited. It mounts the tenant-then-RBAC-scoped
	// query.Engine (SF.7) behind a grounded RCA/NL-query answerer and MCP tool server.
	// Run fills this from config.AI.EnableAPI.
	EnableAISurface bool
	// AIModel is the OPTIONAL, opt-in AI model adapter (F76) the served AI surface reasons
	// through. Nil (the default) is AIR-GAPPED: AI reasoning is OFF, grounding + citations
	// still work, and nothing phones home (the product's "self-hosted / nothing phones
	// home" posture). When set, every prompt crosses the adapter's boundary redactor +
	// residual-entropy refuse-gate before any egress (AN-8 / SURFACE-004). Run leaves it
	// nil unless config.AI.Model opts into a local or cloud provider.
	AIModel *aimodel.Adapter
	// AIModelStatus is the non-secret status metadata the browser/API can show for the
	// configured model: mode, runtime/provider label, model name, endpoint host, and
	// egress class. The full endpoint URL is never echoed.
	AIModelStatus api.AIModelStatus
	// AIMCPIdentity is the workload identity the served MCP server presents (dogfooding
	// the F61 broker). Informational; empty is fine.
	AIMCPIdentity string
	// EnableMCPWriteTools exposes policy-gated MCP write tools. It defaults to false
	// so enabling the AI/MCP read surface never silently grants agent write power.
	EnableMCPWriteTools bool
	// AIRateMax / AIRateWindow bound the per-(caller,tool) MCP call rate
	// (enumeration-abuse protection). Zero selects a conservative default.
	AIRateMax    int
	AIRateWindow time.Duration

	// EnableAgentChannel turns on the served agent steady-state mTLS gRPC channel
	// (WIRE-004 / OPS-005): the running binary mounts an agent-facing gRPC listener at
	// AgentChannelAddr over mutual TLS, an enrolled agent connects to heartbeat its
	// inventory/status and renew its own certificate, and the AGENT CA key is custodied
	// in the signer (stable across restarts). Off (the zero value) leaves the channel
	// unserved (the bootstrap path still mints agent certs, but there is no steady-state
	// listener) so an upgrade does not silently open an agent port. Requires a signer;
	// Build fails closed if enabled without one. Run fills this from config.
	EnableAgentChannel bool
	// AgentChannelAddr is the listen address for the agent gRPC channel (default
	// :9443). Only honored when EnableAgentChannel is true.
	AgentChannelAddr string
	// AgentCACertFile is where the agent CA certificate is persisted, so the agent CA
	// (whose key lives in the signer) is stable across restarts — an agent's pinned CA
	// does not change on a restart (WIRE-004; the AN-4 deviation the audit flagged).
	AgentCACertFile string
	// AgentHeartbeatInterval is the next-beat hint the channel returns to agents. Zero
	// selects a conservative default (30s).
	AgentHeartbeatInterval time.Duration
	// AgentChannelServerName is the DNS SAN the agent-channel server certificate
	// carries (the service name agents set as --server-name). Loopback is always added
	// so a co-located agent / the acceptance test can verify a localhost connection.
	AgentChannelServerName string
}

// Server is the assembled control plane.
type Server struct {
	store     *store.Store
	log       *events.Log
	outbox    *orchestrator.Outbox
	idemGC    *idemgc.Sweeper   // bounds idempotency_keys via the background retention sweep (SPINE-002)
	outboxGC  *outboxgc.Sweeper // bounds the outbox via the background delivered-row purge (SPINE-003)
	obHandler orchestrator.Handler
	handler   http.Handler
	transit   *transitpkg.Service
	codeSign  *servedCodeSigningService
	kmip      KMIPRuntime
	// complianceSigner is a generated locked key used only when the deployment did
	// not supply Deps.ComplianceSigner. Supplied signers are owned by the caller.
	complianceSigner *crypto.LockedSigner

	signer     SignerProvider
	caSigner   crypto.DigestSigner // a *signing.RemoteSigner — the CA key lives in the signer
	caCertDER  []byte
	ocspSigner crypto.DigestSigner
	signAuthz  signing.SignTokenProvider
	signTO     time.Duration

	// Served agent steady-state channel (WIRE-004 / OPS-005): the agent CA key lives
	// in the signer (agentCASigner, AN-4) and is STABLE across restarts (a fixed
	// signer handle), so an agent's pinned CA does not change on a control-plane
	// restart. agentSvc is the heartbeat+renewal gRPC service; agentChannelAddr is the
	// listen address (default :9443). All three are unset (the channel does not serve)
	// when the agent channel is disabled or no signer is available — fail closed.
	agentCASigner          crypto.DigestSigner
	agentCACertDER         []byte
	agentSvc               agentChannelService
	agentChannelAddr       string
	agentChannelServerName string        // SAN the agent verifies (server-name); from config
	agentHeartbeatInterval time.Duration // next-beat hint and stale-heartbeat threshold base
	agentMetrics           *agentChannelMetrics
	agentEnroll            *enroll.Authority // the agent bootstrap-enrollment authority (signs through the agent CA when the channel is on)

	// revoc is the served revocation surface (EXC-REVOKE-01): the OCSP responder,
	// the CRL endpoint, and the CRL freshness scheduler, all signing through the
	// signer (AN-4). It is nil when no issuing CA is provisioned (revocation, like
	// issuance, is then unavailable rather than served by an in-process key).
	revoc *revocationService

	// orch and idem are retained so the served issuance protocols (EXC-WIRE-02) can
	// record minted certs as events (AN-2) and dedupe retried enrollments (AN-5)
	// through the SAME orchestrator + idempotency the API mint uses.
	orch *orchestrator.Orchestrator
	idem *orchestrator.Idempotency
	// defaultProfile is the served certificate-profile binding (PKIGOV-002) the
	// protocol issuer enforces, mirroring the API mint.
	defaultProfile string

	// protocols holds the served issuance-protocol servers (EXC-WIRE-02): ACME, EST,
	// SCEP, CMP, SSH (mounted on the HTTP mux) and the SPIFFE Workload API (served
	// over a UDS by RunSPIFFE). It is nil when no issuing CA is provisioned (protocol
	// serving is then unavailable, like revocation) or when all protocols are
	// disabled. Every protocol mints through the signer-backed, tenant-scoped,
	// event-sourced, idempotent issuance seam (protocolIssuer).
	protocols *servedProtocols
	// attestedIssuance is the served verifier + short-lived X.509-SVID issuer
	// (NHI-02/F30). It is nil unless explicitly configured; the API delegate then
	// returns 503 so upgrades do not silently expose a new minting path.
	attestedIssuance *attestedIssuerService
	// agentBroker is the served policy-gated AI/MCP agent identity broker
	// (NHI-03/F61). Nil makes the API delegate fail closed with 503.
	agentBroker *agentBrokerService
	// ephemeralIssuer is the served approval-gated ephemeral/JIT credential issuer
	// (NHI-04/F25/F33). Nil makes the API delegate fail closed with 503.
	ephemeralIssuer *ephemeralIssuerService
	// pam is the served just-in-time privileged-access broker (PAM-01/F33). Nil
	// makes the API delegate fail closed with 503.
	pam *pamService
	// protoRACertDER / protoRAKeyPKCS8 are the RSA transport key+cert SCEP/CMP use
	// for CMS transport (AN-4: NOT the CA key, which stays in the signer). They are
	// loaded from a sealed, shared RA identity and memoized so SCEP and CMP share one
	// transport key per process.
	protoRACertDER  []byte
	protoRAKeyPKCS8 []byte

	// leafProfile is the served issuing CA's RFC 5280 / BR profile (PKIGOV-001):
	// CDP/AIA/policy pointers and key/EKU/validity constraints stamped on every leaf
	// the served path mints. The zero value preserves the legacy leaf shape (plus an
	// always-present Subject Key Identifier).
	leafProfile crypto.LeafProfile

	// plugins is the served WASM-plugin surface (ARCH-007/SUPPLY-004): operator-
	// supplied connector plugins loaded from a directory, each only after its
	// detached signature verifies against the configured trust policy, and run
	// capability-sandboxed on the plugin host's bounded pool (AN-7). It is nil when
	// the plugin surface is not configured (the prior behavior — a connector.deploy
	// is acknowledged unrouted). Wired into the issuance dispatcher's deploy path.
	plugins *PluginManager

	// connectorRegistry is the trusted native connector registry (CLM-05/F7/F27).
	// It is operator-configured in Deps and is used only by the outbox dispatcher;
	// deployment remains outbox-driven, tenant-scoped, and event-sourced.
	connectorRegistry *connector.Registry
	// notifications is the served notification dispatcher. It fans notification.*
	// outbox rows to operator-configured channels; nil preserves the prior no-channel
	// behavior for notification rows while still letting producers enqueue intents.
	notifications *notify.Dispatcher

	logger     *slog.Logger
	registry   *observ.Registry
	tracer     *observ.Tracer
	readiness  *observ.Readiness
	bulk       *bulkhead.Set
	otlp       *observ.OTLPExporter
	otlpAudit  *observ.OTLPAuditStreamer
	egress     *egress.Guard
	telemetry  *telemetry.Reporter
	federation FederationWorker

	// Audit retention worker (R4.4); nil unless retention + archive are configured.
	retention    *audit.RetentionWorker
	mRetRuns     *observ.Counter
	mRetArchived *observ.Counter
	mRetPruned   *observ.Counter
	mRetFailures *observ.Counter
	mRetLastOK   *observ.Gauge

	// Non-audit personal-data retention worker (PRIVACY-003); nil unless enabled.
	privacyRetention         *orchestrator.PrivacyRetentionWorker
	privacyRetentionInterval time.Duration
	mPrivacyRetRuns          *observ.Counter
	mPrivacyRetRows          *observ.Counter
	mPrivacyRetFailures      *observ.Counter
	mPrivacyRetLastOK        *observ.Gauge

	// Signer telemetry (SF.3): the out-of-process signer can't serve its own
	// /metrics (AN-4), so the control plane samples its health/restarts here.
	mSigner *observ.SignerMetrics

	// Per-feature telemetry (COVER-009): served issuance/revocation/deployment/
	// discovery/ingest operations emit a non-sensitive feature/action/outcome signal,
	// wired into the API via api.WithFeatureObserver. No tenant or secret labels.
	featureMetrics *observ.FeatureMetrics

	// Idempotency-key GC telemetry (SPINE-002): rows reclaimed by the sweep.
	mIdemPurged *observ.Counter

	// Outbox GC telemetry (SPINE-003): delivered rows reclaimed by the purge sweep.
	mOutboxPurged             *observ.Counter
	mOutboxDeliveryTimeouts   *observ.CounterVec
	mOutboxCircuitTransitions *observ.CounterVec

	// Tailing projection worker + lag gauge (SPINE-009): a durable consumer that
	// projects events appended out of band and surfaces projection lag.
	tailWorker          *projections.TailWorker
	mProjLag            *observ.Gauge
	mOutboxReconcileLag *observ.Gauge
	// Event-log durability gauges (RESIL-004): desired vs observed JetStream
	// replicas for the source-of-truth stream, so an under-replicated external log is
	// visible in /readyz and /metrics.
	mEventLogReplicasDesired *observ.Gauge
	mEventLogReplicasActual  *observ.Gauge

	// proj is the projector the snapshot worker writes read-model snapshots through
	// (SPINE-007 / EXC-SCALE-01), retained from Build so RunSnapshotWorker can capture
	// a snapshot at the current checkpoint on the leader's cadence.
	proj *projections.Projector
	// snapshotInterval is how often the leader writes a read-model snapshot; <=0
	// disables the periodic snapshot worker (boot then always does a full checkpoint
	// catch-up). Run fills it from config.HA.SnapshotInterval.
	snapshotInterval time.Duration
	// mSnapshots counts read-model snapshots written by the snapshot worker (SPINE-007),
	// so the snapshot cadence is observable.
	mSnapshots        *observ.Counter
	mSnapshotFailures *observ.Counter
	mSnapshotLastOK   *observ.Gauge

	// CRL freshness scheduler telemetry (EXC-REVOKE-01): CRLs regenerated by the
	// background freshness sweep, so the served CRL's freshness is observable.
	mCRLRegen    *observ.Counter
	mCRLFailures *observ.Counter
	mCRLLastOK   *observ.Gauge

	// Lifecycle automation telemetry (JOURNEY-002): identities queued for served
	// renewal, expiry notifications enqueued, and scheduler failures.
	lifecycleRenewBefore time.Duration
	lifecycleAlertBefore time.Duration
	lifecycleInterval    time.Duration
	mLifecycleQueued     *observ.Counter
	mLifecycleAlerts     *observ.Counter
	mLifecycleFailures   *observ.Counter
	mLifecycleLastOK     *observ.Gauge

	// Fleet-health telemetry (OPS-002): aggregate, low-cardinality gauges/counters
	// for enrollment, heartbeat, and missed-heartbeat thresholds.
	mAgentEnrollments *observ.CounterVec
	mAgentsTotal      *observ.Gauge
	mAgentsStale      *observ.Gauge

	// api is the assembled REST surface, retained so a wiring assertion (e.g. the
	// GAP-006 secrets surface) can confirm the running binary actually mounts a
	// capability. It is the same *api.API behind the served mux.
	api *api.API
}

// Build assembles the control plane over the given dependencies in dependency
// order: it catches the projections up from the event log, constructs the
// orchestrator and API, mounts /healthz + the API + the web UI, and provisions an
// issuing CA whose key is generated inside the signer (never in-process). It does
// not start an HTTP listener — call Handler (tests) or Run (production).
func Build(ctx context.Context, d Deps) (*Server, error) {
	if d.Store == nil || d.Log == nil {
		return nil, errors.New("server: store and log are required")
	}
	signProvider := d.SignTokenProvider
	if signProvider == nil && d.SignAuthorizer != nil {
		signProvider = d.SignAuthorizer
	}
	if signProvider == nil {
		if source, ok := d.Signer.(interface {
			SignTokenProvider() signing.SignTokenProvider
		}); ok {
			signProvider = source.SignTokenProvider()
		}
	}
	s := &Server{
		store:       d.Store,
		log:         d.Log,
		signer:      d.Signer,
		signAuthz:   signProvider,
		signTO:      d.SignTimeout,
		obHandler:   d.OutboxHandler,
		leafProfile: d.LeafProfile,
		registry:    observ.NewRegistry(),
		egress:      d.EgressGuard,
		telemetry:   d.TelemetryReporter,
	}
	s.agentMetrics = newAgentChannelMetrics(s.registry)
	s.mAgentEnrollments = s.registry.CounterVec("trstctl_agent_enrollments_total",
		"Agent bootstrap enrollment attempts by result.", []string{"result"})
	for _, result := range []string{"success", "failed"} {
		s.mAgentEnrollments.WithLabelValues(result)
	}
	if s.signTO <= 0 {
		s.signTO = 10 * time.Second
	}
	proj, err := catchUpReadModel(ctx, d)
	if err != nil {
		return nil, err
	}
	orch, idem, err := s.configureMutationSpine(ctx, d)
	if err != nil {
		return nil, err
	}
	if err := s.configureAgentEnrollment(ctx, d); err != nil {
		return nil, err
	}
	if err := s.configurePluginSurface(ctx, d); err != nil {
		return nil, err
	}
	a, auditSvc, err := s.configureAPI(d, orch, idem)
	if err != nil {
		return nil, err
	}
	if err := s.configureKMIPSurface(d); err != nil {
		return nil, err
	}
	if err := s.configureIssuanceSurfaces(ctx, d, orch, idem); err != nil {
		return nil, err
	}
	if err := s.configureObservability(ctx, d, proj, auditSvc, orch); err != nil {
		return nil, err
	}
	if err := s.configureFederation(ctx, d, proj); err != nil {
		return nil, err
	}
	s.configureRootMux(d, a)
	return s, nil
}

func catchUpReadModel(ctx context.Context, d Deps) (*projections.Projector, error) {
	proj := projections.New(d.Store)
	if restored, err := proj.RestoreFromSnapshot(ctx, d.Log); err != nil {
		return nil, fmt.Errorf("server: restore read model from snapshot: %w", err)
	} else if !restored {
		if err := proj.ProjectCatchUp(ctx, d.Log); err != nil {
			return nil, fmt.Errorf("server: project event log: %w", err)
		}
	}
	return proj, nil
}

func (s *Server) configureMutationSpine(ctx context.Context, d Deps) (*orchestrator.Orchestrator, *orchestrator.Idempotency, error) {
	s.mOutboxDeliveryTimeouts = s.registry.CounterVec(
		"trstctl_outbox_delivery_timeouts_total",
		"Outbox deliveries that exceeded their per-message deadline.",
		[]string{"tenant_id", "destination"},
	)
	s.mOutboxCircuitTransitions = s.registry.CounterVec(
		"trstctl_outbox_circuit_transitions_total",
		"Outbox tenant/destination circuit breaker state transitions.",
		[]string{"tenant_id", "destination", "from", "to"},
	)
	s.outbox = orchestrator.NewOutbox(d.Store,
		orchestrator.WithDeliveryTimeout(d.OutboxDeliveryTimeout),
		orchestrator.WithDeliveryTimeoutObserver(func(m orchestrator.Message) {
			s.mOutboxDeliveryTimeouts.WithLabelValues(m.TenantID, m.Destination).Inc()
		}),
		orchestrator.WithCircuitObserver(func(tr orchestrator.CircuitTransition) {
			s.mOutboxCircuitTransitions.WithLabelValues(tr.TenantID, tr.Destination, string(tr.From), string(tr.To)).Inc()
		}),
	)
	orch := orchestrator.NewOrchestrator(d.Log, d.Store, s.outbox)
	idem := orchestrator.NewIdempotency(d.Store)
	s.orch, s.idem, s.defaultProfile = orch, idem, d.DefaultProfile
	if healed, err := orch.ReconcileOutbox(ctx, d.Log); err != nil {
		return nil, nil, fmt.Errorf("server: reconcile outbox side effects: %w", err)
	} else if healed > 0 && d.Logger != nil {
		d.Logger.Warn("reconciled outbox side effects missed by an append-then-project crash", slog.Int("healed", healed))
	}
	s.idemGC = idemgc.New(d.Store, d.IdempotencyRetention)
	s.outboxGC = outboxgc.New(d.Store, d.OutboxRetention)
	return orch, idem, nil
}

func (s *Server) configureAgentEnrollment(ctx context.Context, d Deps) error {
	if d.EnableAgentChannel {
		if d.Signer == nil || d.Signer.Client() == nil {
			return errors.New("server: agent channel enabled but no signer is available (the agent CA must be custodied in the signer, AN-4)")
		}
		if err := d.Store.WithCAProvisionLock(ctx, func(ctx context.Context) error {
			return s.provisionAgentCA(ctx, d.Signer.Client(), d.AgentCACertFile)
		}); err != nil {
			return fmt.Errorf("server: provision agent CA in signer: %w", err)
		}
		if s.agentCASigner == nil || len(s.agentCACertDER) == 0 {
			return errors.New("server: agent channel enabled but the agent CA could not be provisioned")
		}
	}
	var authority *enroll.Authority
	var err error
	if s.agentCASigner != nil && len(s.agentCACertDER) > 0 {
		authority, err = enroll.NewAuthorityWithIssuer(agentCAIssuer{caSigner: s.agentCASigner, caCertDER: s.agentCACertDER}, storeTokenStore{st: d.Store})
	} else {
		authority, err = enroll.NewAuthority("trstctl Agent Enrollment CA", storeTokenStore{st: d.Store})
	}
	if err != nil {
		return fmt.Errorf("server: create enrollment authority: %w", err)
	}
	s.agentEnroll = authority
	return nil
}

func (s *Server) configureAPI(d Deps, orch *orchestrator.Orchestrator, idem *orchestrator.Idempotency) (*api.API, *audit.Service, error) {
	ea := enrollAuthority{s.agentEnroll}
	// Per-feature telemetry (COVER-009): register the feature metrics on the shared
	// registry (set in Build before this runs) and wire the served API to emit a
	// non-sensitive feature/action/outcome signal on each high-risk feature operation.
	if s.registry == nil {
		s.registry = observ.NewRegistry()
	}
	s.featureMetrics = observ.NewFeatureMetrics(s.registry)
	defaults := []api.Option{
		api.WithAgentEnrollment(ea), api.WithAgentEnroller(ea), api.WithAgentEnrollmentObserver(s.observeAgentEnrollment),
		api.WithAttestedIssuer(s),
		api.WithBroker(s),
		api.WithEphemeralIssuer(s),
		api.WithPAM(s),
		api.WithEventLog(d.Log),
		api.WithLicense(d.License),
		api.WithFeatureObserver(s.featureMetrics.Hook()),
		api.WithCBOM(s.buildCBOMService(d)),
	}
	if d.EnableRemediation {
		defaults = append(defaults,
			api.WithRemediation(),
			api.WithPQCMigration(s.buildPQCMigrationService(d)),
		)
	}
	var auditSvc *audit.Service
	if d.AuditSigningKey != nil {
		auditSvc = audit.NewService(d.Log, d.AuditSigningKey, audit.WithCheckpoints(d.Store), audit.WithPrivacyErasures(d.Store))
		defaults = append(defaults, api.WithAudit(auditSvc))
	}
	if d.RateLimiter != nil {
		defaults = append(defaults, api.WithRateLimiter(d.RateLimiter))
	}
	if s.outbox != nil {
		defaults = append(defaults, api.WithOutboxCircuitStatus(s.outbox.CircuitStates))
	}
	breakglassReconciler, err := buildBreakglassReconciler(d)
	if err != nil {
		return nil, nil, err
	}
	if breakglassReconciler != nil {
		defaults = append(defaults, api.WithBreakglass(breakglassReconciler))
	}
	defaults = append(defaults, api.WithPrivacyRetentionPolicy(d.PrivacyRetentionPolicy))
	defaults = append(defaults, api.WithPrivacyRetentionPolicySource(d.GovernancePolicySource))
	if err := s.configurePolicyGate(d, &defaults); err != nil {
		return nil, nil, err
	}
	authOpt, err := buildBrowserAuth(d.OIDC, d.SAML, d.LDAP, d.SecurityHeaders.TLS, d.AuthHTTPClient, d.Store, d.KEK)
	if err != nil {
		return nil, nil, err
	}
	if authOpt != nil {
		defaults = append(defaults, authOpt)
	}
	scimOpt, err := buildSCIMOption(d.SCIM)
	if err != nil {
		return nil, nil, fmt.Errorf("server: configure SCIM: %w", err)
	}
	if scimOpt != nil {
		defaults = append(defaults, scimOpt)
	}
	if d.EnableSecretsAPI {
		if d.KEK == nil {
			return nil, nil, errors.New("server: secrets API enabled but no KEK provided (envelope encryption at rest is required)")
		}
		defaults = append(defaults, api.WithSecrets(s.buildSecretsBackend(d)))
	}
	if transitSvc := s.buildTransitService(d); transitSvc != nil {
		defaults = append(defaults, api.WithTransit(transitSvc))
	}
	if cs, err := newServedCodeSigningService(d.CodeSigning, d.Store, d.Log, s.outbox); err != nil {
		return nil, nil, fmt.Errorf("server: configure code-signing: %w", err)
	} else if cs != nil {
		s.codeSign = cs
		defaults = append(defaults, api.WithCodeSigning(cs))
	}
	if hierarchySvc := s.buildCAHierarchyService(d); hierarchySvc != nil {
		defaults = append(defaults, api.WithCAHierarchy(hierarchySvc))
	}
	if externalCAs, err := s.buildExternalCAService(d, idem); err != nil {
		return nil, nil, err
	} else if externalCAs != nil {
		defaults = append(defaults, api.WithExternalCAs(externalCAs))
	}
	if mk, err := buildManagedKeyService(d, idem); err != nil {
		return nil, nil, fmt.Errorf("server: configure managed-key lifecycle: %w", err)
	} else if mk != nil {
		defaults = append(defaults, api.WithManagedKeys(mk))
	}
	if d.EnableAISurface {
		defaults = append(defaults, api.WithAISurface(s.buildAISurfaceBackend(d)))
	}
	if complianceSvc, err := s.buildComplianceEvidenceService(d, auditSvc); err != nil {
		return nil, nil, err
	} else if complianceSvc != nil {
		defaults = append(defaults, api.WithComplianceEvidence(complianceSvc))
	}
	a := api.New(d.Store, idem, orch, append(defaults, d.APIOptions...)...)
	s.api = a
	return a, auditSvc, nil
}

func (s *Server) buildTransitService(d Deps) *transitpkg.Service {
	if d.Log == nil {
		return nil
	}
	s.transit = transitpkg.NewService(audit.NewAuditor(d.Log))
	return s.transit
}

func (s *Server) configurePolicyGate(d Deps, defaults *[]api.Option) error {
	s.bulk = d.Bulkhead
	if s.bulk == nil {
		s.bulk = bulkhead.Default()
	}
	gate, approvals, err := buildMutationGate(d, s.bulk)
	if err != nil {
		return err
	}
	*defaults = append(*defaults, api.WithMutationGate(gate))
	if gate.ABAC != nil {
		*defaults = append(*defaults, api.WithABACDenyOverlay(gate.ABAC, gate.ABACEnvironment, gate.ABACNow))
	}
	if approvals != nil {
		*defaults = append(*defaults, api.WithApprovals(approvals))
	}
	return nil
}

func (s *Server) observeAgentEnrollment(result string) {
	if s.mAgentEnrollments == nil {
		return
	}
	switch result {
	case "success", "failed":
	default:
		result = "failed"
	}
	s.mAgentEnrollments.WithLabelValues(result).Inc()
}

func (s *Server) configureIssuanceSurfaces(ctx context.Context, d Deps, orch *orchestrator.Orchestrator, idem *orchestrator.Idempotency) error {
	if err := s.provisionIssuingCA(ctx, d); err != nil {
		return err
	}
	s.connectorRegistry = d.ConnectorRegistry
	ensureCRL, publishCRL, err := s.configureRevocationSurface(ctx, d)
	if err != nil {
		return err
	}
	s.configureOutboxHandler(d, orch, idem, ensureCRL, publishCRL)
	if err := s.configureProtocolSurfaces(ctx, d); err != nil {
		return err
	}
	if err := s.configureAttestedIssuanceSurface(d); err != nil {
		return err
	}
	if err := s.configureAgentBrokerSurface(d); err != nil {
		return err
	}
	if err := s.configureEphemeralIssuanceSurface(d, idem); err != nil {
		return err
	}
	if err := s.configurePAMSurface(d); err != nil {
		return err
	}
	return s.configureAgentChannelSurface(d, idem)
}

func (s *Server) provisionIssuingCA(ctx context.Context, d Deps) error {
	if d.Signer == nil || d.Signer.Client() == nil {
		return nil
	}
	return d.Store.WithCAProvisionLock(ctx, func(ctx context.Context) error {
		if err := s.provisionCA(ctx, d.Signer.Client(), d.CACommonName, d.CACertFile); err != nil {
			return fmt.Errorf("server: provision CA in signer: %w", err)
		}
		return nil
	})
}

func (s *Server) configureRevocationSurface(ctx context.Context, d Deps) (func(context.Context, string) error, func(context.Context, string) error, error) {
	if s.caSigner != nil && len(s.caCertDER) > 0 {
		ocspSigner := s.ocspSigner
		if ocspSigner == nil && d.Signer != nil && d.Signer.Client() != nil {
			var err error
			ocspSigner, err = s.provisionOCSPResponderSigner(ctx, d.Signer.Client(), IssuingCAID())
			if err != nil {
				return nil, nil, fmt.Errorf("server: provision OCSP responder signer: %w", err)
			}
			s.ocspSigner = ocspSigner
		}
		s.revoc = newRevocationService(d.Store, d.Log, IssuingCAID(), s.caSigner, s.caCertDER, ocspSigner)
		if s.revoc != nil {
			s.revoc.ocspMetrics = observ.NewOCSPMetrics(s.registry)
		}
	}
	if s.revoc == nil {
		return nil, nil, nil
	}
	ensureCRL := func(ctx context.Context, tenantID string) error { return s.revoc.ensureCRL(ctx, tenantID) }
	publishCRL := func(ctx context.Context, tenantID string) error {
		_, err := s.revoc.generateCRL(ctx, tenantID)
		return err
	}
	return ensureCRL, publishCRL, nil
}

func (s *Server) configureOutboxHandler(d Deps, orch *orchestrator.Orchestrator, idem *orchestrator.Idempotency, ensureCRL, publishCRL func(context.Context, string) error) {
	if len(d.NotificationChannels) > 0 {
		s.notifications = notify.NewDispatcher(d.NotificationChannels...)
		if d.Store != nil {
			s.notifications.SetPolicyResolver(notify.NewStorePolicyResolver(d.Store))
			s.notifications.SetThresholdDedupLedger(notify.NewStoreThresholdDedupLedger(d.Store, d.Log))
		}
	}
	switch {
	case s.obHandler != nil:
	case s.caSigner != nil:
		s.obHandler = &issuanceDispatcher{issue: s.IssueLeafWithProfile, issueHybrid: s.IssueHybridLeafWithProfile, orch: orch, idem: idem, outbox: s.outbox, store: d.Store, log: d.Log, defaultProfile: d.DefaultProfile, leafProfile: s.leafProfile, ensureCRL: ensureCRL, publishCRL: publishCRL, plugins: s.plugins, connectorRegistry: s.connectorRegistry, notifications: s.notifications, transparency: d.CodeSigning.TransparencyHandler}
	default:
		s.obHandler = &issuanceDispatcher{orch: orch, idem: idem, outbox: s.outbox, store: d.Store, log: d.Log, plugins: s.plugins, connectorRegistry: s.connectorRegistry, notifications: s.notifications, transparency: d.CodeSigning.TransparencyHandler}
	}
}

func (s *Server) configureProtocolSurfaces(ctx context.Context, d Deps) error {
	if s.caSigner == nil || len(s.caCertDER) == 0 {
		return nil
	}
	if err := errors.Join(d.Protocols.ValidateTenantBindings(d.ProtocolTenant)...); err != nil {
		return fmt.Errorf("server: served protocol tenant binding: %w", err)
	}
	protocols, err := s.buildServedProtocols(ctx, d.Protocols, d.ProtocolTenant, d.KEK, d.ACMEValidators)
	if err != nil {
		return fmt.Errorf("server: build served protocols: %w", err)
	}
	s.protocols = protocols
	return nil
}

func (s *Server) configurePluginSurface(ctx context.Context, d Deps) error {
	plugins, err := NewPluginManager(ctx, d.Plugins, d.Log)
	if err != nil {
		return fmt.Errorf("server: load plugins: %w", err)
	}
	s.plugins = plugins
	return nil
}

func (s *Server) configureAttestedIssuanceSurface(d Deps) error {
	svc, err := newAttestedIssuerService(attestedIssuerDeps{
		Config: d.AttestedIssuance, Store: d.Store, Log: d.Log, Orch: s.orch,
		CASigner: s.caSigner, CACertDER: s.caCertDER, CAID: IssuingCAID(),
		Audit: attestedIssuanceAuditor(d.Log),
	})
	if err != nil {
		return err
	}
	s.attestedIssuance = svc
	return nil
}

func (s *Server) configureAgentBrokerSurface(d Deps) error {
	svc, err := newAgentBrokerService(agentBrokerDeps{
		Config: d.AgentBroker, Store: d.Store, Log: d.Log, Orch: s.orch,
		CASigner: s.caSigner, CACertDER: s.caCertDER, CAID: IssuingCAID(),
		Audit: brokerAuditor(d.Log),
	})
	if err != nil {
		return err
	}
	s.agentBroker = svc
	return nil
}

func (s *Server) configureEphemeralIssuanceSurface(d Deps, idem *orchestrator.Idempotency) error {
	svc, err := newEphemeralIssuerService(ephemeralIssuerDeps{
		Config: d.EphemeralIssuance, Store: d.Store, Log: d.Log, Orch: s.orch,
		Idem: idem, Outbox: s.outbox,
		CASigner: s.caSigner, CACertDER: s.caCertDER, CAID: IssuingCAID(),
		Audit: attestedIssuanceAuditor(d.Log),
	})
	if err != nil {
		return err
	}
	s.ephemeralIssuer = svc
	return nil
}

func (s *Server) configurePAMSurface(d Deps) error {
	var sshCA *sshca.CA
	if s.protocols != nil && s.protocols.ssh != nil {
		sshCA = s.protocols.ssh.CA()
	}
	svc, err := newPAMService(pamDeps{
		Config: d.PAM, Store: d.Store, Log: d.Log, SSHCA: sshCA,
		Audit: attestedIssuanceAuditor(d.Log),
	})
	if err != nil {
		return err
	}
	s.pam = svc
	return nil
}

func (s *Server) configureAgentChannelSurface(d Deps, idem *orchestrator.Idempotency) error {
	if !d.EnableAgentChannel || s.agentCASigner == nil || len(s.agentCACertDER) == 0 {
		return nil
	}
	s.agentChannelAddr = d.AgentChannelAddr
	if s.agentChannelAddr == "" {
		s.agentChannelAddr = ":9443"
	}
	s.agentChannelServerName = d.AgentChannelServerName
	s.agentHeartbeatInterval = d.AgentHeartbeatInterval
	agentSvc := &agentService{
		store: d.Store, log: d.Log, orch: s.orch, idem: idem, caSigner: s.agentCASigner,
		caCertDER: s.agentCACertDER, beatInterval: d.AgentHeartbeatInterval,
		metrics: s.agentMetrics,
	}
	wrapped, err := newBulkheadedAgentService(agentSvc, s.bulk.Pool(bulkhead.SubsystemAgent), s.agentMetrics)
	if err != nil {
		return err
	}
	s.agentSvc = wrapped
	return nil
}

func (s *Server) configureObservability(ctx context.Context, d Deps, proj *projections.Projector, auditSvc *audit.Service, orch *orchestrator.Orchestrator) error {
	s.logger = d.Logger
	if s.logger == nil {
		s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if s.registry == nil {
		s.registry = observ.NewRegistry()
	}
	s.otlp = d.OTLPExporter
	if s.otlp != nil {
		s.otlpAudit = observ.NewOTLPAuditStreamer(d.Log, s.otlp)
	}
	s.tracer = observ.NewTracer(observ.CombineExporters(d.TraceExporter, s.otlp))
	s.mIdemPurged = s.registry.CounterVec("trstctl_idempotency_keys_purged_total", "Completed idempotency keys reclaimed by the retention sweep.", nil).WithLabelValues()
	s.mOutboxPurged = s.registry.CounterVec("trstctl_outbox_delivered_purged_total", "Delivered outbox rows reclaimed by the retention sweep.", nil).WithLabelValues()
	s.mProjLag = s.registry.Gauge("trstctl_projection_lag_events", "Number of events the read model is behind the head of the event log.")
	s.tailWorker = projections.NewTailWorker(d.Log, proj, s.mProjLag.Set, 0)
	s.mOutboxReconcileLag = s.registry.Gauge("trstctl_outbox_reconciliation_lag_events", "Number of events after the last boot reconciliation checkpoint.")
	s.mEventLogReplicasDesired = s.registry.Gauge("trstctl_event_log_replicas_desired", "Configured JetStream replica count required for the source-of-truth event stream.")
	s.mEventLogReplicasActual = s.registry.Gauge("trstctl_event_log_replicas_actual", "Observed JetStream replica count on the source-of-truth event stream.")
	s.mAgentsTotal = s.registry.Gauge("trstctl_agents_total", "Total agents currently known to the control plane.")
	s.mAgentsStale = s.registry.Gauge("trstctl_agents_stale_total", "Agents whose last heartbeat is older than two heartbeat intervals.")
	if err := s.sampleEventLogReplicas(ctx); err != nil {
		s.logger.Warn("event-log replica metrics sample failed", slog.String("error", err.Error()))
	}
	if err := s.sampleOutboxReconciliationLag(ctx); err != nil {
		s.logger.Warn("outbox reconciliation lag metrics sample failed", slog.String("error", err.Error()))
	}
	if err := s.sampleAgentFleetHealth(ctx); err != nil {
		s.logger.Warn("agent fleet-health metrics sample failed", slog.String("error", err.Error()))
	}
	s.proj = proj
	s.mSnapshots = s.registry.CounterVec("trstctl_read_model_snapshots_written_total", "Read-model snapshots written by the periodic snapshot worker.", nil).WithLabelValues()
	s.mSnapshotLastOK = s.registry.Gauge("trstctl_read_model_snapshot_last_success_timestamp_seconds", "Unix timestamp of the last successful read-model snapshot.")
	s.mSnapshotFailures = s.registry.CounterVec("trstctl_read_model_snapshot_failures_total", "Read-model snapshot attempts that failed.", nil).WithLabelValues()
	s.mCRLRegen = s.registry.CounterVec("trstctl_crl_regenerated_total", "CRLs regenerated by the served CRL freshness scheduler.", nil).WithLabelValues()
	s.mCRLLastOK = s.registry.Gauge("trstctl_crl_last_regenerated_timestamp_seconds", "Unix timestamp of the last successful CRL regeneration.")
	s.mCRLFailures = s.registry.CounterVec("trstctl_crl_regeneration_failures_total", "CRL freshness scheduler sweeps that failed.", nil).WithLabelValues()
	s.lifecycleRenewBefore = d.LifecycleRenewBefore
	s.lifecycleAlertBefore = d.LifecycleAlertBefore
	s.lifecycleInterval = d.LifecycleInterval
	s.mLifecycleQueued = s.registry.CounterVec("trstctl_lifecycle_renewals_queued_total", "Identities queued by the lifecycle renewal scheduler.", nil).WithLabelValues()
	s.mLifecycleAlerts = s.registry.CounterVec("trstctl_lifecycle_expiry_alerts_queued_total", "Expiry notifications queued by the lifecycle scheduler.", nil).WithLabelValues()
	s.mLifecycleLastOK = s.registry.Gauge("trstctl_lifecycle_scheduler_last_success_timestamp_seconds", "Unix timestamp of the last successful lifecycle scheduler sweep.")
	s.mLifecycleFailures = s.registry.CounterVec("trstctl_lifecycle_scheduler_failures_total", "Lifecycle scheduler sweeps that failed.", nil).WithLabelValues()
	s.configureRetentionWorker(d, auditSvc)
	s.configurePrivacyRetentionWorker(d, orch)
	s.readiness = observ.NewReadiness(s.tracer, s.readinessChecks(ctx, d)...)
	return nil
}

func (s *Server) configureFederation(ctx context.Context, d Deps, proj *projections.Projector) error {
	if d.FederationFactory == nil {
		s.federation = nil
		return nil
	}
	worker, err := d.FederationFactory(ctx, d.Log, proj, d.Store, s.logger)
	if err != nil {
		return fmt.Errorf("server: configure federation: %w", err)
	}
	s.federation = worker
	return nil
}

func (s *Server) configureRetentionWorker(d Deps, auditSvc *audit.Service) {
	if auditSvc == nil || d.AuditRetention <= 0 || d.AuditArchiveDir == "" {
		return
	}
	s.retention = audit.NewRetentionWorker(auditSvc, d.Log, audit.DirArchiver{Dir: d.AuditArchiveDir}, d.Store, d.AuditRetention)
	s.mRetRuns = s.registry.CounterVec("trstctl_audit_retention_runs_total", "Audit retention runs that archived at least one segment.", nil).WithLabelValues()
	s.mRetArchived = s.registry.CounterVec("trstctl_audit_records_archived_total", "Audit records archived to cold storage by the retention worker.", nil).WithLabelValues()
	s.mRetPruned = s.registry.CounterVec("trstctl_audit_records_pruned_total", "Audit records pruned from the hot event log after archival.", nil).WithLabelValues()
	s.mRetFailures = s.registry.CounterVec("trstctl_audit_retention_failures_total", "Audit retention runs that failed.", nil).WithLabelValues()
	s.mRetLastOK = s.registry.Gauge("trstctl_audit_retention_last_success_timestamp_seconds", "Unix timestamp of the last successful audit retention run.")
}

func (s *Server) configurePrivacyRetentionWorker(d Deps, orch *orchestrator.Orchestrator) {
	if !d.PrivacyRetentionEnabled {
		return
	}
	interval := d.PrivacyRetentionInterval
	if interval <= 0 {
		interval = privacy.DefaultRetentionInterval
	}
	s.privacyRetention = orchestrator.NewPrivacyRetentionWorker(orch, d.Store, d.PrivacyRetentionPolicy, d.GovernancePolicySource)
	s.privacyRetentionInterval = interval
	s.mPrivacyRetRuns = s.registry.CounterVec("trstctl_privacy_retention_runs_total", "Non-audit PII retention runs recorded.", nil).WithLabelValues()
	s.mPrivacyRetRows = s.registry.CounterVec("trstctl_privacy_retention_rows_anonymized_total", "Rows pseudonymized by non-audit PII retention.", nil).WithLabelValues()
	s.mPrivacyRetFailures = s.registry.CounterVec("trstctl_privacy_retention_failures_total", "Non-audit PII retention runs that failed.", nil).WithLabelValues()
	s.mPrivacyRetLastOK = s.registry.Gauge("trstctl_privacy_retention_last_success_timestamp_seconds", "Unix timestamp of the last successful non-audit PII retention run.")
}

func (s *Server) readinessChecks(ctx context.Context, d Deps) []observ.Check {
	checks := []observ.Check{
		{Name: "db", Probe: func(ctx context.Context) error { return d.Store.SystemPool().Ping(ctx) }},
		{Name: "nats", Probe: func(ctx context.Context) error { return s.probeEventLog(ctx) }},
	}
	if d.Signer == nil {
		return checks
	}
	checks = append(checks, observ.Check{Name: "signer", Probe: func(ctx context.Context) error {
		c := d.Signer.Client()
		if c == nil || !c.Healthy(ctx) {
			return errors.New("signer unreachable")
		}
		return nil
	}})
	s.mSigner = observ.NewSignerMetrics(s.registry)
	s.sampleSigner(ctx)
	return checks
}

func (s *Server) configureRootMux(d Deps, a *api.API) {
	apiHandler := bulkheadHandler(s.bulk, bulkhead.SubsystemAPI, a)
	heavyHandler := apiHandler
	if s.bulk.Pool(bulkhead.SubsystemQuery) != nil {
		heavyHandler = bulkheadHandler(s.bulk, bulkhead.SubsystemQuery, a)
	}
	cbomHandler := apiHandler
	if s.bulk.Pool(bulkhead.SubsystemCBOM) != nil {
		cbomHandler = bulkheadHandler(s.bulk, bulkhead.SubsystemCBOM, a)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.readiness.Handler())
	mux.Handle("GET /metrics", s.registry.Handler())
	mux.Handle("/api/v1/graph", heavyHandler)
	mux.Handle("/api/v1/graph/", heavyHandler)
	mux.Handle("/api/v1/risk/", heavyHandler)
	mux.Handle("/api/v1/cbom/", cbomHandler)
	mux.Handle("/api/", apiHandler)
	mux.Handle("/v1/", apiHandler)
	mux.Handle("/auth/", apiHandler)
	mux.Handle("/enroll/", apiHandler)
	mux.Handle("/scim/", apiHandler)
	if s.revoc != nil {
		revMux := http.NewServeMux()
		s.revoc.routes(revMux)
		revHandler := bulkheadHandler(s.bulk, bulkhead.SubsystemAPI, revMux)
		mux.Handle("/ocsp/", revHandler)
		mux.Handle("/crl/", revHandler)
	}
	if s.protocols != nil {
		s.protocols.routes(mux, s.bulk)
	}
	mux.Handle("/", webui.Handler(webui.Assets()))
	mw := observ.NewMiddleware(observ.Options{Logger: s.logger, Tracer: s.tracer, Registry: s.registry})
	s.handler = securityHeadersMiddleware(d.SecurityHeaders, mw.Handler(mux))
}

// issuingCAHandle is the stable signer handle for the issuing CA key. Using a
// fixed handle (rather than a random one) lets a restarted, persistent signer
// hand back the same key — so the CA is not silently rotated (R3.2).
const issuingCAHandle = "issuing-ca"

var errPrivilegedSignerAuthorizationRequired = errors.New("server: privileged signer handle requires an independent sign authorization token provider")

// provisionCA establishes the issuing CA whose key lives inside the signer (AN-4;
// the private key never enters the control plane's address space). It is stable
// across restarts (R3.2): if a persisted CA cert exists at caCertFile AND the
// signer still holds the CA key, both are reused. Otherwise it generates the key
// under the fixed handle, self-signs, and persists the cert for future boots.
func (s *Server) provisionCA(ctx context.Context, c *signing.Client, cn, caCertFile string) error {
	if cn == "" {
		cn = "trstctl Issuing CA"
	}

	// Reuse path: persisted cert + a signer that still has the CA key. Bind the
	// reloaded key to the CA-signing purpose so the signer's persisted
	// per-key constraint (SIGNER-002/003) is satisfied across a restart.
	if caCertFile != "" {
		if pemBytes, err := os.ReadFile(caCertFile); err == nil {
			if blk, _ := pem.Decode(pemBytes); blk != nil && blk.Type == "CERTIFICATE" {
				if remote, herr := s.signerForPrivilegedHandle(ctx, c, issuingCAHandle, signing.PurposeCASign); herr == nil {
					s.caSigner = remote
					s.caCertDER = blk.Bytes
					return nil
				}
			}
		}
	}

	// Fresh path: generate the CA key under the fixed handle, bound to the
	// CA-signing purpose so the signer refuses to use it for anything else
	// (SIGNER-002/003: a caller with socket access cannot coerce the CA key into
	// signing SSH/code-signing/leaf-impersonating material), then self-sign and
	// persist.
	remote, err := s.generatePrivilegedKeyHandle(ctx, c, crypto.ECDSAP256, issuingCAHandle,
		[]signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign)
	if err != nil {
		return err
	}
	caDER, err := crypto.SelfSignedCACert(remote, cn, 90*24*time.Hour)
	if err != nil {
		return err
	}
	s.caSigner = remote
	s.caCertDER = caDER
	if caCertFile != "" {
		if err := writeCertPEM(caCertFile, caDER); err != nil {
			return fmt.Errorf("persist CA cert: %w", err)
		}
	}
	return nil
}

// writeCertPEM writes a certificate (DER) PEM-encoded to path (0644 in a 0755
// dir). The CA certificate is public, so it is not a secret.
func writeCertPEM(path string, der []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return os.WriteFile(path, pemBytes, 0o644)
}

func (s *Server) signerForPrivilegedHandle(ctx context.Context, c *signing.Client, handle string, purpose signing.KeyPurpose) (*signing.RemoteSigner, error) {
	if s.signAuthz == nil {
		return nil, errPrivilegedSignerAuthorizationRequired
	}
	return c.SignerForDualControlHandle(ctx, handle, purpose, s.signAuthz)
}

func (s *Server) generatePrivilegedKeyHandle(ctx context.Context, c *signing.Client, algorithm crypto.Algorithm, handle string, allowedPurposes []signing.KeyPurpose, declaredPurpose signing.KeyPurpose) (*signing.RemoteSigner, error) {
	if s.signAuthz == nil {
		return nil, errPrivilegedSignerAuthorizationRequired
	}
	return c.GenerateDualControlKeyHandle(ctx, algorithm, handle, allowedPurposes, declaredPurpose, s.signAuthz)
}

// Handler returns the assembled HTTP handler (for httptest and for Run).
func (s *Server) Handler() http.Handler { return s.handler }

// AirGapEnabled reports whether the assembled server retained an enforcing
// product-wide outbound egress guard.
func (s *Server) AirGapEnabled() bool {
	return s != nil && s.egress != nil && s.egress.Enabled()
}

// CACertPEM returns the issuing CA certificate, or nil when no CA is provisioned.
func (s *Server) CACertPEM() []byte {
	if s.caCertDER == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caCertDER})
}

// OutOfProcessSigning reports whether the issuing CA key is held by the
// out-of-process signer (a *signing.RemoteSigner) rather than in-process. The
// control plane never signs in-process; this is the AN-4 assertion.
func (s *Server) OutOfProcessSigning() bool {
	_, remote := s.caSigner.(*signing.RemoteSigner)
	return s.caSigner != nil && remote
}

// IssueLeaf signs an end-entity certificate from a CSR using the CA key in the
// signer, and returns it PEM-encoded. It FAILS CLOSED — returning an error,
// never an in-process-signed certificate — when the signer is unavailable, slow,
// or returns a signature that does not verify.
func (s *Server) IssueLeaf(ctx context.Context, csrDER []byte, ttl time.Duration) ([]byte, error) {
	return s.IssueLeafWithProfile(ctx, csrDER, ttl, s.leafProfile)
}

// IssueLeafWithProfile signs an end-entity certificate under the supplied
// per-issuance leaf profile. Served API/protocol paths pass the active tenant
// certificate-profile constraints here so the signer emits exactly the EKUs that
// were validated, not the legacy default set.
func (s *Server) IssueLeafWithProfile(ctx context.Context, csrDER []byte, ttl time.Duration, leafProfile crypto.LeafProfile) ([]byte, error) {
	if s.caSigner == nil || s.caCertDER == nil {
		return nil, errors.New("server: issuance unavailable — no out-of-process signer (fail closed)")
	}
	// The signer must be reachable and serving before we attempt to sign.
	if s.signer != nil {
		c := s.signer.Client()
		hctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		healthy := c != nil && c.Healthy(hctx)
		cancel()
		if !healthy {
			return nil, errors.New("server: signer unavailable (fail closed)")
		}
	}
	// Bound the signing operation so a slow signer fails closed instead of
	// hanging the request.
	type result struct {
		der []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		// Sign under the served issuing profile (PKIGOV-001/002): the leaf carries
		// the configured CDP/AIA/policy pointers + an always-present SKI, and any
		// profile constraints (validity/EKU/DNS-suffix) are enforced before signing.
		der, err := crypto.SignLeafFromCSRWithProfile(s.caCertDER, s.caSigner, csrDER, ttl, leafProfile)
		ch <- result{der, err}
	}()
	select {
	case <-time.After(s.signTO):
		return nil, errors.New("server: signer timed out (fail closed)")
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("server: issuance failed: %w", r.err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.der}), nil
	}
}

// IssueHybridLeaf signs an end-entity certificate from a classical CSR and adds
// a verifiable ML-DSA-44 + ECDSA-P256 composite transition extension. The CA
// signature still goes through the out-of-process signer; the leaf remains a
// stock ECDSA certificate so existing TLS clients can use it while PQ-aware
// clients validate the dual public-key binding.
func (s *Server) IssueHybridLeaf(ctx context.Context, csrDER []byte, ttl time.Duration) ([]byte, error) {
	return s.IssueHybridLeafWithProfile(ctx, csrDER, ttl, s.leafProfile)
}

// IssueHybridLeafWithProfile is IssueHybridLeaf with an explicit served leaf
// profile, matching IssueLeafWithProfile for tenant profile enforcement.
func (s *Server) IssueHybridLeafWithProfile(ctx context.Context, csrDER []byte, ttl time.Duration, leafProfile crypto.LeafProfile) ([]byte, error) {
	if s.caSigner == nil || s.caCertDER == nil {
		return nil, errors.New("server: hybrid issuance unavailable — no out-of-process signer (fail closed)")
	}
	if s.signer != nil {
		c := s.signer.Client()
		hctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		healthy := c != nil && c.Healthy(hctx)
		cancel()
		if !healthy {
			return nil, errors.New("server: signer unavailable (fail closed)")
		}
	}
	type result struct {
		der []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		der, err := pqc.SignHybridLeafFromCSRWithProfile(s.caCertDER, s.caSigner, csrDER, ttl, leafProfile)
		ch <- result{der, err}
	}()
	select {
	case <-time.After(s.signTO):
		return nil, errors.New("server: signer timed out (fail closed)")
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("server: hybrid issuance failed: %w", r.err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.der}), nil
	}
}

// RevocationServed reports whether the served revocation surface (OCSP + CRL +
// scheduler) is active — i.e. an issuing CA is provisioned so OCSP/CRL sign
// through the signer. It is the EXC-REVOKE-01 wiring assertion.
func (s *Server) RevocationServed() bool { return s.revoc != nil }

// ServedProtocols reports the protocol surfaces the running binary serves
// (EXC-WIRE-02): the subset of {acme,est,scep,cmp,tsa,ssh,spiffe} actually mounted,
// in a stable order. Empty when no issuing CA is provisioned or all protocols are
// disabled. It is the EXC-WIRE-02 wiring assertion (and is logged at startup).
func (s *Server) ServedProtocols() []string {
	if s.protocols == nil {
		return nil
	}
	return append([]string(nil), s.protocols.names...)
}

// sshProtocolForTest returns the served SSH protocol surface, or nil when SSH is not
// served. Exported (test-only) so the acceptance test can drive the served SSH CA.
func (s *Server) sshProtocolForTest() *sshProtocol {
	if s.protocols == nil {
		return nil
	}
	return s.protocols.ssh
}

// OCSPResponse produces a signed OCSP response (DER) for an OCSP request (DER)
// under tenantID, by driving the exact served responder path. It is exported so
// the assembled-server acceptance test can exercise the served OCSP code without
// an HTTP round-trip. Returns an error when revocation is not served.
func (s *Server) OCSPResponse(ctx context.Context, tenantID string, reqDER []byte) ([]byte, error) {
	if s.revoc == nil {
		return nil, errors.New("server: revocation not served (no issuing CA)")
	}
	return s.revoc.respondOCSP(ctx, tenantID, reqDER)
}

// GenerateCRL generates, signs, persists, and returns the next CRL (DER) for
// tenantID, driving the exact served CRL path. Exported for the acceptance test.
// Returns an error when revocation is not served.
func (s *Server) GenerateCRL(ctx context.Context, tenantID string) ([]byte, error) {
	if s.revoc == nil {
		return nil, errors.New("server: revocation not served (no issuing CA)")
	}
	return s.revoc.generateCRL(ctx, tenantID)
}

// RegenerateDueCRLs runs a single CRL freshness sweep (the scheduler's per-tick
// body) and returns how many CRLs were regenerated. Exported so the acceptance
// test can drive the scheduler deterministically rather than waiting on the
// ticker. A no-op (0, nil) when revocation is not served.
func (s *Server) RegenerateDueCRLs(ctx context.Context) (int, error) {
	if s.revoc == nil {
		return 0, nil
	}
	return s.revoc.regenerateDue(ctx)
}

// health reports readiness: the API is up; if a signer is configured it must be
// reachable.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if s.signer != nil {
		c := s.signer.Client()
		hctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		ok := c != nil && c.Healthy(hctx)
		cancel()
		if !ok {
			http.Error(w, `{"status":"degraded","signer":"unavailable"}`, http.StatusServiceUnavailable)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// dispatchInterval is how often the running dispatcher sweeps the outbox for due
// entries.
const dispatchInterval = time.Second

// RunDispatcher runs the outbox dispatcher continuously until ctx is cancelled,
// delivering due entries (issuance, deployment, notifications) on a short
// interval — so external effects happen while the process runs, not only at
// shutdown. Per-entry failures are recorded on the row for retry inside Dispatch;
// only a transient store/transport fault returns from Dispatch, and the next tick
// retries. It is meant to run in its own goroutine.
func (s *Server) RunDispatcher(ctx context.Context) {
	t := time.NewTicker(dispatchInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.dispatchOnce(ctx)
		}
	}
}

// dispatchOnce sweeps the outbox once, routed through the outbox bulkhead pool so
// delivery participates in backpressure (a saturated pool sheds the tick rather
// than piling up sweeps) and is drained on shutdown (AN-7). Concurrent sweeps are
// safe — the outbox claims rows FOR UPDATE SKIP LOCKED. With no outbox pool
// configured it sweeps directly.
func (s *Server) dispatchOnce(ctx context.Context) {
	run := func() { _, _ = s.outbox.Dispatch(ctx, s.obHandler) }
	if s.bulk == nil || s.bulk.Pool(bulkhead.SubsystemOutbox) == nil {
		run()
		return
	}
	_ = s.bulk.Submit(bulkhead.SubsystemOutbox, run)
}

// retentionInterval is how often the audit retention worker sweeps for records
// past the retention window. Archival is a slow, low-urgency maintenance task, so
// the cadence is hourly (the window itself is typically days to years).
const retentionInterval = time.Hour

// RunRetention runs the audit retention worker on the retention cadence until ctx
// is cancelled (R4.4). It is a no-op when retention/archive are not configured, so
// it is always safe to start in its own goroutine. It sweeps once on start so a
// freshly booted, long-overdue deployment archives promptly rather than waiting a
// full interval.
func (s *Server) RunRetention(ctx context.Context) {
	if s.retention == nil {
		return
	}
	// RunRetentionOnce logs and records its own errors; the loop ignores the return
	// and the next tick retries (same pattern as the outbox dispatcher).
	_, _ = s.RunRetentionOnce(ctx)
	t := time.NewTicker(retentionInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = s.RunRetentionOnce(ctx)
		}
	}
}

// RunPrivacyRetention runs the non-audit PII retention worker on its configured
// cadence until ctx is cancelled. It sweeps once on start so overdue terminal
// personal data is pseudonymized promptly after boot.
func (s *Server) RunPrivacyRetention(ctx context.Context) {
	if s.privacyRetention == nil {
		return
	}
	_, _ = s.RunPrivacyRetentionOnce(ctx)
	interval := s.privacyRetentionInterval
	if interval <= 0 {
		interval = privacy.DefaultRetentionInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = s.RunPrivacyRetentionOnce(ctx)
		}
	}
}

// idemGCInterval is how often the idempotency-key GC sweep runs (SPINE-002).
// Reclaiming expired keys is a low-urgency maintenance task and the retention
// window is days, so an hourly cadence keeps the table bounded without pressure.
const idemGCInterval = time.Hour

// RunIdempotencyGC reclaims completed idempotency keys past the retention window
// on a fixed cadence until ctx is cancelled (SPINE-002), keeping idempotency_keys
// bounded for a high-volume fleet. AN-5 holds within the window. It sweeps once on
// start so a long-running deployment reclaims promptly, then on each tick; a sweep
// error is logged and the next tick retries (same pattern as the outbox dispatcher
// and the audit retention worker). It is meant to run in its own goroutine.
func (s *Server) RunIdempotencyGC(ctx context.Context) {
	if s.idemGC == nil {
		return
	}
	s.idemGCOnce(ctx)
	t := time.NewTicker(idemGCInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.idemGCOnce(ctx)
		}
	}
}

// idemGCOnce runs a single idempotency-key reclamation sweep and records the
// count. Errors are logged, not returned: the loop retries on the next tick.
func (s *Server) idemGCOnce(ctx context.Context) {
	n, err := s.idemGC.Sweep(ctx)
	if err != nil {
		s.logger.Warn("idempotency-key gc sweep failed", slog.String("error", err.Error()))
		return
	}
	if n > 0 {
		if s.mIdemPurged != nil {
			s.mIdemPurged.Add(float64(n))
		}
		s.logger.Info("idempotency-key gc reclaimed expired keys", slog.Int64("reclaimed", n))
	}
}

// outboxGCInterval is how often the outbox delivered-row purge runs (SPINE-003).
// Reclaiming delivered rows is a low-urgency maintenance task and the retention
// window is hours-to-days, so an hourly cadence keeps the table bounded without
// pressure (same cadence as the idempotency-key GC).
const outboxGCInterval = time.Hour

// RunOutboxGC reclaims delivered outbox rows past the retention window on a fixed
// cadence until ctx is cancelled (SPINE-003), keeping the outbox table bounded for a
// high-volume fleet. At-least-once delivery (AN-6) is unaffected — only already-
// delivered rows are reclaimed. It sweeps once on start so a long-running deployment
// reclaims promptly, then on each tick; a sweep error is logged and the next tick
// retries (same pattern as the idempotency-key GC and the audit retention worker).
// It is meant to run in its own goroutine.
func (s *Server) RunOutboxGC(ctx context.Context) {
	if s.outboxGC == nil {
		return
	}
	s.outboxGCOnce(ctx)
	t := time.NewTicker(outboxGCInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.outboxGCOnce(ctx)
		}
	}
}

// outboxGCOnce runs a single outbox delivered-row reclamation sweep and records the
// count. Errors are logged, not returned: the loop retries on the next tick.
func (s *Server) outboxGCOnce(ctx context.Context) {
	n, err := s.outboxGC.Sweep(ctx)
	if err != nil {
		s.logger.Warn("outbox gc sweep failed", slog.String("error", err.Error()))
		return
	}
	if n > 0 {
		if s.mOutboxPurged != nil {
			s.mOutboxPurged.Add(float64(n))
		}
		s.logger.Info("outbox gc reclaimed delivered rows", slog.Int64("reclaimed", n))
	}
}

// RunProjectionTail runs the tailing projection worker until ctx is cancelled
// (SPINE-009): a durable consumer that projects any event appended out of band and
// keeps the projection-lag gauge current. A tail error (e.g. a poison event leaving
// the durable cursor stuck) is logged and the loop re-enters after a short backoff;
// the lag gauge plateaus, which is the operator's divergence signal. It is meant to
// run in its own goroutine.
func (s *Server) RunProjectionTail(ctx context.Context) {
	if s.tailWorker == nil {
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		if err := s.tailWorker.Run(ctx); err != nil && ctx.Err() == nil {
			s.logger.Warn("projection tail worker stopped; retrying", slog.String("error", err.Error()))
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}
}

// RunFederation imports configured peer event logs into the local log and projects
// them until ctx is cancelled. It is a leader-only worker under Run, so one replica
// owns peer imports while all replicas can serve the replicated read model.
func (s *Server) RunFederation(ctx context.Context) {
	if s.federation == nil {
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		if err := s.federation.Run(ctx); err != nil && ctx.Err() == nil {
			s.logger.Warn("federation worker stopped; retrying", slog.String("error", err.Error()))
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}
}

// RunOTLPAuditStream exports event-sourced audit records to the configured
// OTLP collector until ctx is cancelled. It is a leader-only worker under Run, so
// HA deployments do not duplicate the same event stream from every replica. The
// exporter carries stream sequence attributes, so downstream SIEMs can dedupe on
// restart and alert on gaps.
func (s *Server) RunOTLPAuditStream(ctx context.Context) {
	if s.otlpAudit == nil {
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		if err := s.otlpAudit.Run(ctx); err != nil && ctx.Err() == nil {
			s.logger.Warn("otlp audit streamer stopped; retrying", slog.String("error", err.Error()))
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		return
	}
}

func (s *Server) probeEventLog(ctx context.Context) error {
	err := s.log.Ping(ctx)
	if sampleErr := s.sampleEventLogReplicas(ctx); sampleErr != nil && err == nil {
		err = sampleErr
	}
	if sampleErr := s.sampleOutboxReconciliationLag(ctx); sampleErr != nil && err == nil {
		err = sampleErr
	}
	return err
}

func (s *Server) sampleEventLogReplicas(ctx context.Context) error {
	if s.log == nil {
		return nil
	}
	status, err := s.log.StreamReplicaStatus(ctx)
	if err != nil {
		return err
	}
	if s.mEventLogReplicasDesired != nil {
		s.mEventLogReplicasDesired.Set(float64(status.Desired))
	}
	if s.mEventLogReplicasActual != nil {
		s.mEventLogReplicasActual.Set(float64(status.Actual))
	}
	return nil
}

func (s *Server) sampleOutboxReconciliationLag(ctx context.Context) error {
	if s.log == nil || s.store == nil {
		return nil
	}
	head, err := s.log.LastSequence(ctx)
	if err != nil {
		return err
	}
	reconciled, err := s.store.OutboxReconciliationCheckpoint(ctx)
	if err != nil {
		return err
	}
	lag := uint64(0)
	if head > reconciled {
		lag = head - reconciled
	}
	if s.mOutboxReconcileLag != nil {
		s.mOutboxReconcileLag.Set(float64(lag))
	}
	return nil
}

const defaultAgentHeartbeatInterval = 30 * time.Second

func (s *Server) agentStaleBefore() time.Time {
	interval := s.agentHeartbeatInterval
	if interval <= 0 {
		interval = defaultAgentHeartbeatInterval
	}
	return time.Now().Add(-2 * interval)
}

func (s *Server) sampleAgentFleetHealth(ctx context.Context) error {
	if s.store == nil || s.mAgentsTotal == nil || s.mAgentsStale == nil {
		return nil
	}
	health, err := s.store.AgentFleetHealth(ctx, s.agentStaleBefore())
	if err != nil {
		return err
	}
	s.mAgentsTotal.Set(float64(health.Total))
	s.mAgentsStale.Set(float64(health.Stale))
	return nil
}

const agentFleetMonitorInterval = 30 * time.Second

// RunAgentFleetMonitor keeps the low-cardinality fleet-health gauges fresh for
// alerting. It reads only aggregate counts from the agents read model; heartbeats
// themselves remain event-sourced and projected by the agent channel.
func (s *Server) RunAgentFleetMonitor(ctx context.Context) {
	if err := s.sampleAgentFleetHealth(ctx); err != nil && s.logger != nil {
		s.logger.Warn("agent fleet-health metrics sample failed", slog.String("error", err.Error()))
	}
	t := time.NewTicker(agentFleetMonitorInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.sampleAgentFleetHealth(ctx); err != nil && s.logger != nil {
				s.logger.Warn("agent fleet-health metrics sample failed", slog.String("error", err.Error()))
			}
		}
	}
}

// SetSnapshotInterval configures how often RunSnapshotWorker writes a read-model
// snapshot (SPINE-007). Run calls it from config.HA.SnapshotInterval; <=0 disables
// the worker. It is a plain setter so the production composition and a test can both
// drive the cadence.
func (s *Server) SetSnapshotInterval(d time.Duration) { s.snapshotInterval = d }

// RunSnapshotWorker periodically captures a read-model snapshot at the current
// projection checkpoint until ctx is cancelled (SPINE-007 / EXC-SCALE-01), so a later
// cold boot / DR restore rehydrates from it and replays ONLY the tail — making boot
// constant-time w.r.t. the lifetime event count. It is a LEADER-ONLY worker (gated by
// leader election in Run, RESIL-004): a single replica writes snapshots so concurrent
// captures cannot race. It is a no-op when the interval is <=0 (snapshots disabled).
// A capture error is logged and the next tick retries (same pattern as the other
// background workers). It is meant to run in its own goroutine.
func (s *Server) RunSnapshotWorker(ctx context.Context) {
	if s.proj == nil || s.snapshotInterval <= 0 {
		return
	}
	t := time.NewTicker(s.snapshotInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.snapshotOnce(ctx)
		}
	}
}

// snapshotOnce writes one read-model snapshot and records the count. Errors are
// logged, not returned: the log is the source of truth (AN-2), so a failed snapshot
// only forgoes the boot accelerator — the next tick retries and boot still falls back
// to a full catch-up if no snapshot is available.
func (s *Server) snapshotOnce(ctx context.Context) {
	n, err := s.proj.Snapshot(ctx)
	if err != nil {
		if s.mSnapshotFailures != nil {
			s.mSnapshotFailures.Inc()
		}
		s.logger.Warn("read-model snapshot failed", slog.String("error", err.Error()))
		return
	}
	if n > 0 {
		if s.mSnapshots != nil {
			s.mSnapshots.Add(float64(n))
		}
		if s.mSnapshotLastOK != nil {
			s.mSnapshotLastOK.Set(float64(time.Now().Unix()))
		}
		s.logger.Info("read-model snapshot written", slog.Int("tenants", n))
	}
}

// RunCRLScheduler runs the served CRL freshness scheduler until ctx is cancelled
// (EXC-REVOKE-01): it regenerates each tenant's CRL ahead of its nextUpdate (and
// generates a first one on demand), so the CRL the CDP serves is never stale. CRLs
// are signed through the out-of-process signer (AN-4). It is a no-op when no
// issuing CA is provisioned (revocation is not served), so it is always safe to
// start in its own goroutine. A sweep error is logged and the next tick retries
// (the same pattern as the outbox dispatcher and the other background workers).
func (s *Server) RunCRLScheduler(ctx context.Context) {
	if s.revoc == nil {
		return
	}
	s.revoc.runScheduler(ctx, func(_ string, n int, err error) {
		if err != nil {
			if s.mCRLFailures != nil {
				s.mCRLFailures.Inc()
			}
			s.logger.Warn("crl scheduler sweep failed", slog.String("error", err.Error()))
			return
		}
		if n > 0 {
			if s.mCRLRegen != nil {
				s.mCRLRegen.Add(float64(n))
			}
			if s.mCRLLastOK != nil {
				s.mCRLLastOK.Set(float64(time.Now().Unix()))
			}
			s.logger.Info("crl scheduler regenerated CRLs", slog.Int("regenerated", n))
		}
	})
}

const defaultLifecycleSchedulerInterval = time.Minute

// RunLifecycleScheduler runs the leader-only certificate renewal scheduler until
// ctx is cancelled (JOURNEY-002/F6/NOTIF-01). It does not sign certificates or send
// notifications directly. It scans deployed X.509 identities with active served
// certificates expiring within the configured renewal window and queues the normal
// deployed->renewing lifecycle transition; the outbox then mints the successor
// through ca.renew. It also scans active certificates inside the alert window and
// queues notification.expiry rows; the outbox then fans them to configured notify
// channels. A sweep error is logged and the next tick retries.
func (s *Server) RunLifecycleScheduler(ctx context.Context) {
	if (s.lifecycleRenewBefore <= 0 && s.lifecycleAlertBefore <= 0) || s.orch == nil || s.store == nil {
		return
	}
	_, _ = s.RunLifecycleOnce(ctx)
	interval := s.lifecycleInterval
	if interval <= 0 {
		interval = defaultLifecycleSchedulerInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = s.RunLifecycleOnce(ctx)
		}
	}
}

// RunLifecycleOnce performs one lifecycle-scheduler sweep and returns how many
// identities were moved to renewing. Expiry alerts are also enqueued when configured,
// but are counted on their own metric so callers that care about renewal behavior keep
// the old return contract. Exported for served-path tests.
func (s *Server) RunLifecycleOnce(ctx context.Context) (int, error) {
	if (s.lifecycleRenewBefore <= 0 && s.lifecycleAlertBefore <= 0) || s.orch == nil || s.store == nil {
		return 0, nil
	}
	now := time.Now().UTC()
	queued := 0
	if s.lifecycleRenewBefore > 0 {
		cutoff := now.Add(s.lifecycleRenewBefore)
		tenants, err := s.store.TenantsWithRenewalIdentityCandidates(ctx, cutoff, now)
		if err != nil {
			s.observeLifecycleSweep(queued, 0, err)
			return 0, err
		}
		for _, tenant := range tenants {
			candidates, err := s.store.ListRenewalIdentityCandidates(ctx, tenant, cutoff, now)
			if err != nil {
				s.observeLifecycleSweep(queued, 0, err)
				return queued, err
			}
			seen := make(map[string]struct{}, len(candidates))
			for _, candidate := range candidates {
				ident := candidate.Identity
				if _, ok := seen[ident.ID]; ok {
					continue
				}
				seen[ident.ID] = struct{}{}
				reason, due := lifecycleRenewalReason(candidate.Certificate, now, cutoff)
				if !due {
					continue
				}
				if err := s.orch.Transition(ctx, tenant, ident.ID, orchestrator.StateRenewing, reason); err != nil {
					if errors.Is(err, orchestrator.ErrInvalidTransition) {
						continue
					}
					s.observeLifecycleSweep(queued, 0, err)
					return queued, err
				}
				queued++
			}
		}
	}
	alerted, err := s.runLifecycleAlertsOnce(ctx)
	if err != nil {
		s.observeLifecycleSweep(queued, alerted, err)
		return queued, err
	}
	s.observeLifecycleSweep(queued, alerted, nil)
	return queued, nil
}

func (s *Server) runLifecycleAlertsOnce(ctx context.Context) (int, error) {
	if s.lifecycleAlertBefore <= 0 || s.notifications == nil || s.store == nil || s.outbox == nil || s.log == nil {
		return 0, nil
	}
	now := time.Now().UTC()
	tenants, err := s.store.TenantsWithAlertableCertificates(ctx, now, now.Add(s.lifecycleAlertBefore))
	if err != nil {
		return 0, err
	}
	m := lifecycle.NewManager(s.store, nil, s.outbox, s.idem, s.log, lifecycle.Config{AlertBefore: s.lifecycleAlertBefore})
	alerted := 0
	for _, tenant := range tenants {
		n, err := m.AlertExpiring(ctx, tenant)
		if err != nil {
			return alerted, err
		}
		alerted += n
	}
	return alerted, nil
}

func lifecycleRenewalReason(cert store.Certificate, now, fixedCutoff time.Time) (string, bool) {
	if cert.NotAfter == nil {
		return "", false
	}
	notAfter := cert.NotAfter.UTC()
	if cert.NotBefore != nil {
		notBefore := cert.NotBefore.UTC()
		info := ari.RenewalInfo{SuggestedWindow: ari.SuggestWindow(notBefore, notAfter, now, false)}
		if ari.RenewNow(info, now) {
			return fmt.Sprintf("scheduled renewal from ARI window %s..%s",
				info.SuggestedWindow.Start.Format(time.RFC3339),
				info.SuggestedWindow.End.Format(time.RFC3339)), true
		}
	}
	if notAfter.Before(fixedCutoff) {
		return "scheduled renewal before " + fixedCutoff.Format(time.RFC3339), true
	}
	return "", false
}

func (s *Server) observeLifecycleSweep(queued, alerted int, err error) {
	if err != nil {
		if s.mLifecycleFailures != nil {
			s.mLifecycleFailures.Inc()
		}
		if s.logger != nil {
			s.logger.Warn("lifecycle scheduler sweep failed", slog.String("error", err.Error()))
		}
		return
	}
	if queued > 0 {
		if s.mLifecycleQueued != nil {
			s.mLifecycleQueued.Add(float64(queued))
		}
		if s.logger != nil {
			s.logger.Info("lifecycle scheduler queued renewals", slog.Int("queued", queued))
		}
	}
	if alerted > 0 {
		if s.mLifecycleAlerts != nil {
			s.mLifecycleAlerts.Add(float64(alerted))
		}
		if s.logger != nil {
			s.logger.Info("lifecycle scheduler queued expiry alerts", slog.Int("alerts", alerted))
		}
	}
	if s.mLifecycleLastOK != nil {
		s.mLifecycleLastOK.Set(float64(time.Now().Unix()))
	}
}

// signerMonitorInterval is how often the control plane samples the out-of-process
// signer's health and restart count for the SF.3 metrics.
const signerMonitorInterval = 5 * time.Second

// RunSignerMonitor periodically samples the signer's health/restarts into the
// shared metrics registry until ctx is cancelled (SF.3). It is a no-op when no
// signer is configured, so it is always safe to start in its own goroutine, and
// it stops promptly on shutdown (the graceful-shutdown contract).
func (s *Server) RunSignerMonitor(ctx context.Context) {
	if s.mSigner == nil {
		return
	}
	t := time.NewTicker(signerMonitorInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sampleSigner(ctx)
		}
	}
}

// sampleSigner records one signer telemetry sample: whether a healthy signer
// client is currently available, and the supervisor's cumulative restart count
// when the provider exposes one. The health probe is time-bounded so a hung
// signer cannot stall the sampler.
func (s *Server) sampleSigner(ctx context.Context) {
	if s.mSigner == nil {
		return
	}
	up := false
	if s.signer != nil {
		if c := s.signer.Client(); c != nil {
			hctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			up = c.Healthy(hctx)
			cancel()
		}
	}
	var restarts uint64
	if r, ok := s.signer.(interface{ Restarts() uint64 }); ok {
		restarts = r.Restarts()
	}
	s.mSigner.Observe(up, restarts)
}

// RunRetentionOnce performs one audit retention pass and records its outcome as
// metrics. It is exported so the assembled server can be driven through a single
// archive/prune cycle in tests. A nil worker (retention not configured) is a
// no-op. Errors are logged, not fatal — the next sweep retries.
func (s *Server) RunRetentionOnce(ctx context.Context) (audit.Summary, error) {
	if s.retention == nil {
		return audit.Summary{}, nil
	}
	sum, err := s.retention.RunOnce(ctx)
	if err != nil {
		if s.mRetFailures != nil {
			s.mRetFailures.Inc()
		}
		s.logger.Error("audit retention run failed", slog.String("error", err.Error()))
		return sum, err
	}
	if s.mRetLastOK != nil {
		s.mRetLastOK.Set(float64(time.Now().Unix()))
	}
	if s.mRetArchived != nil {
		s.mRetArchived.Add(float64(sum.RecordsArchived))
		s.mRetPruned.Add(float64(sum.RecordsPruned))
		if sum.SegmentsArchived > 0 {
			s.mRetRuns.Inc()
		}
	}
	if sum.RecordsArchived > 0 {
		s.logger.Info("audit retention archived and pruned records",
			slog.Int("records", sum.RecordsArchived), slog.Int("tenants", sum.TenantsProcessed))
	}
	return sum, nil
}

// RunPrivacyRetentionOnce performs one non-audit PII retention pass and records
// its outcome as metrics. A nil worker is a no-op.
func (s *Server) RunPrivacyRetentionOnce(ctx context.Context) (orchestrator.PrivacyRetentionSummary, error) {
	if s.privacyRetention == nil {
		return orchestrator.PrivacyRetentionSummary{}, nil
	}
	sum, err := s.privacyRetention.RunOnce(ctx)
	if err != nil {
		if s.mPrivacyRetFailures != nil {
			s.mPrivacyRetFailures.Inc()
		}
		s.logger.Error("privacy retention run failed", slog.String("error", err.Error()))
		return sum, err
	}
	if s.mPrivacyRetLastOK != nil {
		s.mPrivacyRetLastOK.Set(float64(time.Now().Unix()))
	}
	if s.mPrivacyRetRuns != nil {
		s.mPrivacyRetRuns.Add(float64(sum.RunsRecorded))
	}
	if s.mPrivacyRetRows != nil {
		s.mPrivacyRetRows.Add(float64(sum.RowsAnonymized))
	}
	if sum.RowsAnonymized > 0 {
		s.logger.Info("privacy retention pseudonymized stale personal data",
			slog.Int("rows", sum.RowsAnonymized), slog.Int("tenants", sum.TenantsProcessed))
	}
	return sum, nil
}

// Drain delivers any pending outbox entries through the configured handler — the
// shutdown step that guarantees no enqueued external effect is lost (AN-6).
func (s *Server) Drain(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := s.outbox.Dispatch(ctx, s.obHandler)
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
	}
}

// Shutdown drains the subsystem pools and the outbox, then closes the event log
// and datastore in order — the graceful drain that completes in-flight work
// without loss (R2.3 / AN-7).
func (s *Server) Shutdown(ctx context.Context) error {
	var errs []error
	// Stop accepting new pool work and drain everything already in flight (AN-7
	// graceful drain) before the final outbox sweep.
	if s.bulk != nil {
		s.bulk.Close()
	}
	if err := s.Drain(ctx); err != nil {
		errs = append(errs, fmt.Errorf("drain outbox: %w", err))
	}
	// Release the WASM plugin runtimes and their bounded pool (ARCH-007).
	if s.plugins != nil {
		if err := s.plugins.Close(ctx); err != nil {
			errs = append(errs, fmt.Errorf("close plugins: %w", err))
		}
	}
	if s.transit != nil {
		s.transit.Destroy()
	}
	if s.kmip != nil {
		s.kmip.Close()
	}
	if s.complianceSigner != nil {
		s.complianceSigner.Destroy()
	}
	if s.otlp != nil {
		if err := s.otlp.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close otlp exporter: %w", err))
		}
	}
	if s.federation != nil {
		if err := s.federation.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close federation: %w", err))
		}
	}
	if s.log != nil {
		if err := s.log.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close event log: %w", err))
		}
	}
	if s.store != nil {
		s.store.Close()
	}
	return errors.Join(errs...)
}
