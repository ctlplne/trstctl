// SPDX-License-Identifier: MPL-2.0

// Package server is the composition root of the trstctl control plane (S7.7): it
// wires the configuration, datastore, event log, projections, orchestrator, and
// REST API into one serving process, provisions an issuing CA whose key lives in
// the out-of-process signer (AN-4), and shuts everything down in order. It is the
// integration seam — it introduces no new product capability, only the assembly
// of capabilities that already exist and are tested as packages.
package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/agent/enroll"
	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authmethod"
	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/breakglass"
	"trstctl.com/trstctl/internal/broker"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/cloudauth"
	"trstctl.com/trstctl/internal/codesign"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/idemgc"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/lifecycle"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/observ/otlp"
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
	"trstctl.com/trstctl/internal/tenantseal"
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

// BackgroundWorker is a licensed background loop mounted through the tagged EE
// attach seam. Core owns only lifecycle and supervision; the implementation lives
// outside core.
type BackgroundWorker interface {
	Name() string
	Run(context.Context) error
}

// Deps are the wired dependencies of the serving control plane. Tests inject an
// embedded store/log and an in-process signer; production wires the real ones.
// IdempotencyResultMigrator is the readiness wall that drains historical
// migration-only result codecs before the default HTTP surface opens.
type IdempotencyResultMigrator interface {
	MigrateAll(context.Context) ([]store.IdempotencyResultProtectionStatus, error)
}

type Deps struct {
	// BackupDirectory is the full-backup directory the served DR posture
	// reports on (epic J2). Empty means none is configured, which the API
	// serves as such rather than reporting an invented path as a missing
	// backup.
	BackupDirectory string
	// RestoreDrill runs one restore drill and returns its attestation (J2).
	//
	// A function rather than a config struct because the drill needs the
	// PostgreSQL DSN to build a throwaway database, and handing the whole
	// configuration to the Server so it could reach one field would give every
	// other part of the Server the same reach. The composition root already
	// holds the config; it closes over what the drill needs and passes nothing
	// else. Nil means this deployment cannot drill, which the DR surface
	// reports rather than hides.
	RestoreDrill func(context.Context) (backup.DrillAttestation, error)
	// RestoreDrillInterval is how often it runs. Zero takes the default;
	// negative disables it.
	RestoreDrillInterval time.Duration
	RestoreDrillRPO      time.Duration
	RestoreDrillRTO      time.Duration
	Store                *store.Store
	Log                  *events.Log
	Signer               SignerProvider // may be nil → issuance is unavailable (fail closed)
	// SignerMode is the topology the production composition actually opened:
	// "child" when this process supervises the isolated process, or "external"
	// when it connected to a separately deployed signer. Empty preserves the
	// child default for direct/test Build callers that supply a signer.
	SignerMode        string
	SignAuthorizer    *crypto.SignAuthorizer    // test/eval token provider; production should use SignTokenProvider
	SignTokenProvider signing.SignTokenProvider // independent approval-token source for dual-control signer handles
	// SignerKeyStoreDir is the local signer provisioning/keystore directory when
	// the deployment has one. Licensed APIs may use it through generic, file-based
	// provisioning seams; external signer deployments can leave it empty or point it
	// at their operator-managed shared directory.
	SignerKeyStoreDir string
	// ManagedKeyFactory is supplied only by the tagged EE attach seam when the
	// Enterprise BYOK feature is licensed and configured. Nil leaves the
	// /api/v1/managed-keys/* surface unmounted, so Community receives 404.
	ManagedKeyFactory ManagedKeyServiceFactory
	// ManagedKeyCustody is the secret-free enabled/provider posture used by the
	// planning API. The composition root never passes provider credentials or paths.
	ManagedKeyCustody api.ManagedKeyCustodyConfiguration
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
	// ServiceNowBindings are operator-approved ITSM egress bindings. The served API
	// fails closed for ServiceNow ticket requests that do not match one of them.
	ServiceNowBindings []api.ServiceNowBinding
	// OutboundEnvCredentialRefs are operator-approved env-backed credential refs
	// that API-authored discovery/response integrations may place into outbox work.
	OutboundEnvCredentialRefs []string
	// FederationFactory is supplied only by the tagged EE attach seam when the
	// Enterprise HA-support feature is licensed. Leader election, projection
	// checkpoints, and advisory locks remain core and free.
	FederationFactory FederationFactory
	// GovernanceFactory is supplied only by the tagged EE attach seam when the
	// Enterprise governance feature is licensed. Nil keeps compliance evidence
	// routes unmounted; audit/privacy mechanisms stay core.
	GovernanceFactory GovernanceFactory
	// BrokerIssuancePrecondition is supplied only by the tagged EE attach seam when
	// the Enterprise agent-delegation feature is licensed. It is the feature-neutral
	// chain-bound issuance precondition attached to the broker via
	// broker.WithIssuancePrecondition; the broker consults it ONLY on its chain-bound
	// issuance path. Nil leaves the seam inert, so the free single-hop attested badge
	// (broker.Issue) is unaffected and Community/core-only deployments run no
	// chain-bound precondition (INV-A10 zero removal). AGID-07b consumes this when it
	// wires the broker.
	BrokerIssuancePrecondition broker.IssuancePrecondition
	// BrokerTaskEnvelopeGate is supplied only by the tagged EE attach seam
	// (B-7). It verifies an AGID-05 task envelope as a precondition of broker
	// issuance and returns the digest the credential binds. Nil in Community /
	// core-only builds, where a request carrying an envelope is REFUSED rather
	// than silently issued unscoped.
	BrokerTaskEnvelopeGate BrokerTaskEnvelopeGate
	// IssuanceAdmission is a feature-neutral pre-mint policy seam for served issuance
	// and renewal side effects. Nil leaves core behavior unchanged; tagged edition
	// attach code may supply a hook that admits or refuses only operations whose
	// observed-state inputs match its policy.
	IssuanceAdmission AdmissionHook
	// ProviderHandler is supplied only by the tagged EE attach seam when the Provider
	// plane is licensed. Nil keeps /provider/* dark with 404 instead of falling
	// through to the web UI.
	ProviderHandler http.Handler
	// TelemetryReporter is the opt-in usage reporter (COMP-04). Nil means telemetry
	// is off; Run only wires it when telemetry.enabled is explicitly true, and the
	// reporter payload is fixed to anonymized, bucketed, non-PII fields.
	TelemetryReporter         *telemetry.Reporter
	OutboxHandler             orchestrator.Handler // delivers outbox entries; defaults to a no-op success
	APIOptions                []api.Option         // auth/audit/etc.
	License                   *license.Manager     // offline edition state exposed by GET /v1/editions
	EnableRemediation         bool                 // Enterprise remediation: incident execution and guided remediation routes
	EnablePCAS                bool                 // Enterprise PCAS: proof-carrying algorithm succession (ee/succession); the succession API/orchestrator wiring keys off this
	LicensedAPIOptionsFactory LicensedAPIOptionsFactory
	LicensedOutboxFactory     LicensedOutboxFactory
	LicensedBackgroundWorkers []BackgroundWorker
	LicensedProjectionOptions []projections.Option
	LicensedLeafSigner        LicensedLeafSigner
	LicensedCSRInspector      LicensedCSRInspector
	LicensedCSRParser         LicensedCSRParser
	LicensedSPIFFESVIDFactory LicensedSPIFFESVIDFactory
	SignTimeout               time.Duration // per-issuance signer deadline (slow → fail closed)
	CACommonName              string
	CACertFile                string             // authoritative persisted issuing-CA cert path; reused across restarts so the CA is stable (R3.2)
	CAPublicCertFile          string             // optional certificate-only mirror for clients outside the private data volume
	LeafProfile               crypto.LeafProfile // served-leaf RFC 5280/BR profile: CDP/AIA/policy + constraints (PKIGOV-001/002)
	DefaultProfile            string             // certificate-profile name enforced on the served mint when it resolves (PKIGOV-002); empty = none
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
	// BreakglassCACertDER and BreakglassPublicKeyDER pin verifier material for
	// break-glass reconciliation and for the online issuance audit check. The route
	// never trusts verifier material supplied by the caller.
	BreakglassCACertDER    []byte
	BreakglassPublicKeyDER []byte
	// BreakglassIssuer/Ceremonies/Rotation are the production-assembled online
	// lifecycle. BreakglassOfflineIssuer is retained only for the standalone
	// offline service adapter; shipped assembly binds the interfaces below to a
	// persisted purpose-constrained signer handle.
	BreakglassIssuer        api.BreakglassIssuer
	BreakglassCeremonies    api.BreakglassCeremonyService
	BreakglassRotation      api.BreakglassRotationService
	BreakglassReconciler    api.BreakglassReconciler
	BreakglassOfflineIssuer *breakglass.Service
	// RequireApproval turns on served dual-control for privileged transitions (issue
	// and revoke): the transition is denied unless a DISTINCT approver has recorded an
	// approval (the served half of RED-004 / SEC-002). Backed by the store's issuance
	// approval tables under RLS (AN-1). Off (the zero value) keeps the prior behavior.
	RequireApproval bool
	// RequiredApprovals is the number of distinct approvals a privileged action needs
	// when RequireApproval is on. Zero defaults to 2 (dual control), matching
	// internal/approval.
	RequiredApprovals int
	AuditSigningKey   *jose.SigningKey // public + signer-RPC capability only; private audit key stays in trstctl-signer (AUD-63)
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
	// OwnershipAttestationCadence makes owner accountability a steady-state
	// lifecycle authority and schedules one re-attestation notification per stale
	// verification edge. Zero disables it for source-compatible embedders; the
	// shipped Run composition always supplies the validated config value.
	OwnershipAttestationCadence time.Duration
	// AgentClaimableJobKinds are the estate-touching job kinds agents may claim
	// over the channel (A1). Empty — the default — means the job ledger is served
	// but hands nothing out, which is correct until an agent-side executor for a
	// kind exists. Values outside the allowlist in AgentClaimableJobKinds are
	// dropped: an operator cannot move the control plane's own effects onto a host
	// by naming them here.
	AgentClaimableJobKinds []string
	// LifecycleLeafValidity is the reference leaf lifetime the CA calendar (H5)
	// measures a parent authority's remaining horizon against, so it can say
	// "this parent can no longer issue a full-length leaf" before anyone notices
	// their certificates quietly getting shorter. Zero selects
	// lifecycle.DefaultLeafValidity. It is a yardstick, not an issuance limit.
	LifecycleLeafValidity time.Duration
	// LifecycleInterval is the scheduler cadence. Zero selects a conservative default.
	LifecycleInterval time.Duration

	// MaintenanceWindows restrict when the renewal scheduler may queue work
	// (epic D6). Empty means unrestricted.
	MaintenanceWindows lifecycle.WindowSet

	// EndpointVerificationInterval is how often endpoints are re-probed to
	// confirm they are still serving what was deployed (epic D2). Zero selects
	// defaultEndpointVerificationInterval.
	//
	// This is the interval the epic's acceptance criterion is measured against:
	// a renewal that never lands live must be detected within one of these.
	EndpointVerificationInterval time.Duration
	// NotificationChannels are the operator-configured served notification sinks
	// (NOTIF-01/F29). They are driven only by notification.* outbox rows; the
	// scheduler never calls a channel directly, preserving AN-6 at-least-once delivery.
	NotificationChannels []notify.Notifier
	// notificationChannelOwner follows production-created channel credentials from
	// buildRunDeps through edition attachment and Build. It is deliberately private:
	// successful Build transfers ownership to the notification Dispatcher, while
	// every earlier failure closes through this one token.
	notificationChannelOwner *notificationChannelOwnership
	Logger                   *slog.Logger    // structured access log sink (R2.2); nil discards
	TraceExporter            observ.Exporter // completed-span sink (R2.2); nil is a no-op
	OTLPExporter             *otlp.Exporter
	Bulkhead                 *bulkhead.Set   // per-subsystem bounded pools (R2.3/AN-7); nil uses bulkhead.Default()
	RateLimiter              api.RateLimiter // per-tenant rate limiter (R2.3); nil disables rate limiting
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

	// UpstreamDV carries the unattended domain-validation seam for ACME
	// authorities configured with upstream_dns01 (epic B7). The external-CA
	// factories capture it during dependency construction; the Server fills it
	// once the DNS-01 automation exists, so an order arriving before that fails
	// closed rather than appearing to validate. Nil disables upstream DV, which
	// is the pre-B7 behaviour: issuance only for already-authorized identifiers.
	UpstreamDV *upstreamDVHolder

	// ConnectorRegistry configures the trusted, in-process native deployment
	// connectors (CLM-05/F7/F27). When set, connector.deploy outbox rows whose
	// connector name is registered here are delivered by the running binary through
	// the connector SDK sandbox and recorded as event-sourced delivery receipts.
	// Empty leaves plugin-owned rows to the signed WASM surface; any row without a
	// loaded owner fails closed and stays pending.
	ConnectorRegistry *connector.Registry
	// ConnectorRightSize applies usage-backed entitlement reductions through a
	// tenant-bound external connector and verifies the effective scopes by readback.
	ConnectorRightSize RightSizeMutator

	// Plugins configures the served WASM-plugin surface (EXC-WIRE-05, closing
	// ARCH-007/SUPPLY-004): the directory of operator-supplied connector plugins, the
	// trusted Ed25519 keys that admit a signed module, optional content-digest pins,
	// and the capability grant they run under. The zero value leaves the surface OFF
	// (an otherwise unowned connector.deploy fails closed). When configured, Build
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
	// values under at rest (R3.1/AN-8). It also seals connector.deploy outbox payloads
	// carrying private keys and the SCEP/CMP RA transport identity when those protocol
	// endpoints are enabled. These served surfaces need it retained for the process
	// lifetime. The plaintext secret never touches the store — only sealed blobs do.
	KEK sealKeyWrapper
	// TransitKeyringDir is where the transit keyring is sealed at rest. Empty
	// keeps the keyring in memory only, which means keys do not survive a
	// restart — see buildTransitService.
	TransitKeyringDir string
	// TenantCrypto routes every tenant-owned secret-bearing value through the
	// RLS-scoped tenant key-domain fence. Production Run always supplies it;
	// narrow embed tests may retain the legacy KEK-only composition.
	TenantCrypto tenantseal.Access
	// IdempotencyResultProtector is the tenant-bound outer envelope for every
	// cached mutation response. Production Run always sets it before Build. Nil is
	// retained only for narrow test/library compositions that do not claim the
	// default-binary readiness contract.
	IdempotencyResultProtector  orchestrator.ResultProtector
	IdempotencyResultMigrator   IdempotencyResultMigrator
	IdempotencyResultFleetReady bool
	// TenantKeyDomains is the CORE, tenant-scoped cryptographic custody
	// lifecycle. Production Run wires it from the same wrapper registry and
	// result-protection resolver used by every cached mutation response.
	TenantKeyDomains api.TenantKeyDomainLifecycle
	// SecretsAuthSecret is the HMAC key the served machine-login token method
	// (authmethod.TokenMethod) verifies a workload token against (F58). It is []byte and
	// never logged (AN-8). When empty, the login route reports the method is not
	// configured (the secret store / share / pki sub-features still work). Run derives
	// it from a configured key file.
	SecretsAuthSecret []byte
	// SecretsAuthTokenTenantID and SecretsAuthTokenScopes make the builtin token
	// verifier an explicit, least-privilege tenant authority.
	SecretsAuthTokenTenantID string
	SecretsAuthTokenScopes   []string
	// MachineAuthMethods returns tenant-scoped workload login methods such as
	// Kubernetes SAT, AWS IAM, GCP, Azure, OIDC, and JWT. Empty keeps those methods
	// off while preserving the HMAC token method when SecretsAuthSecret is configured.
	MachineAuthMethods func(tenantID string) []authmethod.Method
	// DynamicSecretProviders are the configured dynamic-secret providers exposed by
	// /api/v1/secrets/leases (F65). Empty keeps the route fail-closed.
	DynamicSecretProviders []dynsecret.Provider
	// TenantDynamicSecretProviders is the production tenant-bound registry. When
	// present it takes precedence over the legacy static slice above, which remains
	// for embedded compositions and existing tests.
	TenantDynamicSecretProviders DynamicSecretProviderRegistry
	// SecretRotators retain configured static-credential engines for library users
	// and a future durable worker. The served HTTP route refuses them before any
	// provider effect; only connector rotation is executable today (F37).
	SecretRotators map[string]rotation.Rotator
	// SecretSyncTargets are the configured external secret-sync destinations exposed
	// by /api/v1/secrets/syncs (F68). Empty keeps the route fail-closed.
	SecretSyncTargets map[string]*secretsync.Target
	// TenantSecretSyncTargets is the production tenant-bound registry. It prevents
	// target names and upstream credentials from crossing tenant boundaries.
	TenantSecretSyncTargets SecretSyncTargetRegistry
	// CloudTokenMinter is the shared locked-memory refresh cache used by
	// workload-federated secret-sync targets. Server Shutdown owns it.
	CloudTokenMinter *cloudauth.Minter
	// SecretScanGitleaksBin points at the pinned Gitleaks binary used by
	// POST /api/v1/secrets/scans (SEC-07/F39). Empty resolves
	// TRSTCTL_GITLEAKS_BIN/tools/bin/gitleaks/PATH at request time.
	SecretScanGitleaksBin string
	// SecretScanRoots confines served scan targets/custom rules to explicitly
	// mounted operator-owned trees. Empty means the process working directory.
	SecretScanRoots []string
	// SecretScanner overrides the pinned Gitleaks runner for tests and embedded
	// compositions. Production leaves it nil so both the REST scan route and the
	// repository-scan outbox worker use the same pinned binary resolution.
	SecretScanner secretScanner
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
	// AgentChannelPublicAddress is the operator-declared host:port agents dial.
	// It is intentionally distinct from the listen address because container and
	// load-balancer publication commonly rewrite the port.
	AgentChannelPublicAddress string
	// AgentHTTPRenewalAddr is the listen address for the embedded-agent HTTP renewal
	// mTLS listener (default :9444). Only honored when EnableAgentChannel is true,
	// because it uses the same signer-custodied agent CA and client certificates.
	AgentHTTPRenewalAddr string
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
	store             *store.Store
	log               *events.Log
	audit             *audit.Service
	outbox            *orchestrator.Outbox
	outboxWake        chan struct{}
	idemGC            *idemgc.Sweeper   // bounds idempotency_keys via the background retention sweep (SPINE-002)
	outboxGC          *outboxgc.Sweeper // bounds the outbox via the background delivered-row purge (SPINE-003)
	obHandler         orchestrator.Handler
	handler           http.Handler
	acmeDNS01         *servedACMEDNS01Automation
	transit           *transitpkg.Service
	transitStore      *transitpkg.Store
	transitStateMu    sync.RWMutex
	transitStateFound bool
	// codeSignGate is the production adapter over the live OPA evaluator and
	// distinct-approver store assembled by configurePolicyGate.
	codeSignGate  codesign.Gate
	codeSign      *servedCodeSigningService
	ctSubmit      *servedCTSubmissionService
	kmip          KMIPRuntime
	kmipStateMu   sync.RWMutex
	kmipListening bool
	// complianceSigner is a generated locked key used only when the deployment did
	// not supply Deps.ComplianceSigner. Supplied signers are owned by the caller.
	complianceSigner *crypto.LockedSigner
	cloudTokenMinter *cloudauth.Minter
	tenantCrypto     tenantseal.Access

	signer SignerProvider
	// signerTopology is explicit because both child and external runtimes expose
	// the same SignerProvider client. Inferring topology from that interface made
	// an external Compose signer appear as an in-process child in System health.
	signerTopology string
	caSigner       crypto.DigestSigner // a *signing.RemoteSigner — the CA key lives in the signer
	caCertDER      []byte
	caHierarchy    *caHierarchyService
	ocspSigner     crypto.DigestSigner
	signAuthz      signing.SignTokenProvider
	signTO         time.Duration

	// Served agent steady-state channel (WIRE-004 / OPS-005): the agent CA key lives
	// in the signer (agentCASigner, AN-4) and is STABLE across restarts (a fixed
	// signer handle), so an agent's pinned CA does not change on a control-plane
	// restart. agentSvc is the heartbeat+renewal gRPC service; agentChannelAddr is the
	// listen address (default :9443). All three are unset (the channel does not serve)
	// when the agent channel is disabled or no signer is available — fail closed.
	agentCASigner           crypto.DigestSigner
	agentCACertDER          []byte
	agentSvc                agentChannelService
	agentChannelAddr        string
	agentHTTPRenewalAddr    string
	agentHTTPRenewalHandler http.Handler
	agentChannelServerName  string        // SAN the agent verifies (server-name); from config
	agentHeartbeatInterval  time.Duration // next-beat hint and stale-heartbeat threshold base
	agentMetrics            *agentChannelMetrics
	agentEnroll             *enroll.Authority // the agent bootstrap-enrollment authority (signs through the agent CA when the channel is on)

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
	// protocolProfile is non-nil only for the explicit eval preset. It owns the
	// event-replayed activation gate exposed to the first-run wizard.
	protocolProfile *evalProtocolProfileControl
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
	leafProfile               crypto.LeafProfile
	licensedLeafSigner        LicensedLeafSigner
	licensedCSRInspector      LicensedCSRInspector
	licensedCSRParser         LicensedCSRParser
	licensedSPIFFESVIDFactory LicensedSPIFFESVIDFactory

	// plugins is the served WASM-plugin surface (ARCH-007/SUPPLY-004): operator-
	// supplied connector plugins loaded from a directory, each only after its
	// detached signature verifies against the configured trust policy, and run
	// capability-sandboxed on the plugin host's bounded pool (AN-7). It is nil when
	// the plugin surface is not configured, in which case an otherwise unowned
	// connector.deploy fails closed. Wired into the issuance dispatcher's deploy path.
	plugins *PluginManager

	// connectorRegistry is the trusted native connector registry (CLM-05/F7/F27).
	// It is operator-configured in Deps and is used only by the outbox dispatcher;
	// deployment remains outbox-driven, tenant-scoped, and event-sourced.
	connectorRegistry *connector.Registry
	// externalCAs is the served external-CA registry. Provider calls are delivered
	// by the outbox dispatcher so upstream issue/poll/download side effects are
	// durable and retried with provider idempotency.
	externalCAs *externalCARegistry
	// notifications is the served notification dispatcher. It fans notification.*
	// outbox rows to operator-configured channels; nil preserves the prior no-channel
	// behavior for notification rows while still letting producers enqueue intents.
	notifications             *notify.Dispatcher
	licensedBackgroundWorkers []BackgroundWorker
	// serviceNowBindings is the operator's approved ITSM egress allow-list. The
	// CMDB scheduler resolves the private-egress grant from it at RUN time
	// rather than from a copy taken when the schedule was configured, so
	// narrowing the grant takes effect on the next sync instead of on the next
	// time somebody happens to re-save the schedule.
	serviceNowBindings []api.ServiceNowBinding

	logger    *slog.Logger
	registry  *observ.Registry
	tracer    *observ.Tracer
	readiness *observ.Readiness
	// startedAt stamps process start for the B-5 system readout's uptime.
	startedAt  time.Time
	bulk       *bulkhead.Set
	mBulkheads *observ.BulkheadMetrics
	otlp       *otlp.Exporter
	otlpAudit  *otlp.AuditStreamer
	egress     *egress.Guard
	telemetry  *telemetry.Reporter
	federation FederationWorker

	// Audit retention worker (R4.4); nil unless retention + archive are configured.
	retention    *audit.RetentionWorker
	mRetRuns     *observ.Counter
	mRetArchived *observ.Counter
	mRetPruned   *observ.Counter
	mRetRetained *observ.Counter
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
	mOutboxDeadLetter   *observ.GaugeVec
	// outboxDeadLetterSeen tracks label tuples previously reported non-zero so a
	// drained bucket is zeroed on the next sample instead of going stale.
	outboxDeadLetterSeen map[string][2]string
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
	lifecycleRenewBefore        time.Duration
	lifecycleAlertBefore        time.Duration
	lifecycleLeafValidity       time.Duration
	ownershipAttestationCadence time.Duration
	lifecycleInterval           time.Duration
	// endpointVerificationInterval is how often endpoints are re-probed (D2).
	// Zero uses defaultEndpointVerificationInterval.
	endpointVerificationInterval time.Duration
	// restoreDrill runs one drill; nil means this deployment cannot drill (J2).
	// restoreDrillInterval is zero for the default and negative when disabled.
	// lastRestoreDrill stays nil until one has run, which is what lets the DR
	// surface tell "never drilled" from "drilled and found nothing wrong".
	restoreDrill         func(context.Context) (backup.DrillAttestation, error)
	restoreDrillInterval time.Duration
	restoreDrillRPO      time.Duration
	restoreDrillRTO      time.Duration
	restoreDrillSigner   *jose.SigningKey
	restoreDrillRunMu    sync.Mutex
	restoreDrillMu       sync.Mutex
	lastRestoreDrill     *backup.DrillAttestation
	// maintenanceWindows restrict when the scheduler may renew (D6). Empty
	// means unrestricted — an operator who configured no windows did not ask
	// for a freeze.
	maintenanceWindows lifecycle.WindowSet
	mLifecycleQueued   *observ.Counter
	mLifecycleAlerts   *observ.Counter
	mLifecycleFailures *observ.Counter
	mLifecycleLastOK   *observ.Gauge

	// Fleet-health telemetry (OPS-002): aggregate, low-cardinality gauges/counters
	// for enrollment, heartbeat, and missed-heartbeat thresholds.
	mAgentEnrollments *observ.CounterVec
	mAgentsTotal      *observ.Gauge
	mAgentsStale      *observ.Gauge
	// Application-secret crash recovery is tenant-isolated. A custody outage
	// leaves only that tenant's commands fenced, degrades readiness, and increments
	// this unlabeled gauge without exposing tenant or secret names.
	mApplicationSecretReconcileBlocked  *observ.Gauge
	mApplicationSecretReconcileDegraded *observ.Gauge

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
func resolveSignTokenProvider(d Deps) signing.SignTokenProvider {
	if d.SignTokenProvider != nil {
		return d.SignTokenProvider
	}
	if d.SignAuthorizer != nil {
		return d.SignAuthorizer
	}
	if source, ok := d.Signer.(interface {
		SignTokenProvider() signing.SignTokenProvider
	}); ok {
		return source.SignTokenProvider()
	}
	return nil
}

func Build(ctx context.Context, d Deps) (_ *Server, err error) {
	notificationOwner := ensureNotificationChannelOwnership(&d)
	var s *Server
	defer func() {
		if err == nil {
			// configureOutboxHandler always creates the dispatcher for a valid
			// Store-backed server. It is now the sole successful-path owner.
			notificationOwner.transferToDispatcher()
			return
		}
		if d.CloudTokenMinter != nil {
			d.CloudTokenMinter.Close()
		}
		if s != nil && s.notifications != nil {
			// The dispatcher was constructed before a later Build step failed.
			// Hand ownership to it, then close it exactly once here because no
			// Server will be returned for Shutdown to own.
			notificationOwner.transferToDispatcher()
			s.notifications.Close()
			return
		}
		notificationOwner.closeUntransferred()
	}()
	if d.Store == nil || d.Log == nil {
		return nil, errors.New("server: store and log are required")
	}
	if d.RestoreDrill != nil && d.AuditSigningKey == nil {
		return nil, errors.New("server: restore drill requires the isolated audit-evidence signer")
	}
	signProvider := resolveSignTokenProvider(d)
	s = &Server{
		store:                     d.Store,
		log:                       d.Log,
		outboxWake:                make(chan struct{}, 1),
		signer:                    d.Signer,
		signerTopology:            d.SignerMode,
		signAuthz:                 signProvider,
		signTO:                    d.SignTimeout,
		obHandler:                 d.OutboxHandler,
		leafProfile:               d.LeafProfile,
		licensedLeafSigner:        d.LicensedLeafSigner,
		licensedCSRInspector:      d.LicensedCSRInspector,
		licensedCSRParser:         d.LicensedCSRParser,
		licensedSPIFFESVIDFactory: d.LicensedSPIFFESVIDFactory,
		licensedBackgroundWorkers: d.LicensedBackgroundWorkers,
		serviceNowBindings:        d.ServiceNowBindings,
		registry:                  observ.NewRegistry(),
		egress:                    d.EgressGuard,
		telemetry:                 d.TelemetryReporter,
		cloudTokenMinter:          d.CloudTokenMinter,
		tenantCrypto:              d.TenantCrypto,
		restoreDrillSigner:        d.AuditSigningKey,
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
	privacyRecovery := orchestrator.NewOrchestrator(
		d.Log,
		d.Store,
		orchestrator.NewOutbox(d.Store),
		historyRewriteOrchestratorOptions(d.Store, d.AuditSigningKey)...,
	)
	if completed, recoveryErr := privacyRecovery.RecoverPrivacySubjectErasurePreparations(ctx); recoveryErr != nil {
		return nil, fmt.Errorf(
			"server: recover prepared privacy subject erasures before read-model restore: %w",
			recoveryErr,
		)
	} else if completed > 0 && d.Logger != nil {
		d.Logger.Warn(
			"completed privacy subject erasures interrupted after durable preparation",
			slog.Int("completed", completed),
		)
	}
	proj, err := catchUpReadModel(ctx, d)
	if err != nil {
		return nil, err
	}
	orch, idem, err := s.configureMutationSpine(ctx, d, proj)
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
	if healed, reconcileErr := a.ReconcileApplicationSecretMutationFences(ctx); reconcileErr != nil {
		if !errors.Is(reconcileErr, api.ErrApplicationSecretMutationReconcileBlocked) {
			return nil, fmt.Errorf("server: reconcile application-secret mutation fences: %w", reconcileErr)
		}
		if d.Logger != nil {
			d.Logger.Warn("application-secret crash recovery is custody-blocked; affected commands remain fenced and readiness will be degraded",
				slog.Int("blocked", a.ApplicationSecretMutationReconcileBlockedCount()))
		}
	} else if healed > 0 && d.Logger != nil {
		d.Logger.Warn("reconciled application-secret commands missed by an append/project crash", slog.Int("healed", healed))
	}
	if healed, reconcileErr := reconcileApprovedTargetEventFences(ctx, d.Store, d.Log, orch); reconcileErr != nil {
		if !errors.Is(reconcileErr, store.ErrPrivacySubjectErasurePreparationActive) {
			return nil, fmt.Errorf("server: reconcile approved target event fences: %w", reconcileErr)
		}
		if d.Logger != nil {
			d.Logger.Warn("approved-target crash recovery is blocked by an active privacy erasure preparation; commands remain fenced")
		}
	} else if healed > 0 && d.Logger != nil {
		d.Logger.Warn("reconciled approved certificate/code-signing commands missed by an append/project crash",
			slog.Int("healed", healed))
	}
	if err := s.configureKMIPSurface(d); err != nil {
		return nil, err
	}
	if err := s.configureIssuanceSurfaces(ctx, d, orch, idem); err != nil {
		return nil, err
	}
	a.AttachProtocolProfileControl(s.protocolProfile)
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
	options := append([]projections.Option(nil), d.LicensedProjectionOptions...)
	if d.OwnershipAttestationCadence > 0 {
		options = append(options, projections.WithOwnershipAttestationCadence(d.OwnershipAttestationCadence))
	}
	if d.AuditSigningKey != nil {
		options = append(options, projections.WithRestoreDrillVerificationKeys(d.AuditSigningKey.JWKS()))
	}
	proj := projections.New(d.Store, options...)
	if _, err := proj.RestoreFromSnapshot(ctx, d.Log); err != nil {
		return nil, fmt.Errorf("server: restore read model from snapshot: %w", err)
	}
	if err := proj.ProjectCatchUp(ctx, d.Log); err != nil {
		return nil, fmt.Errorf("server: project event log: %w", err)
	}
	if err := d.Store.ValidateSecretRotationScheduleStartupAuthority(ctx,
		func(resolveCtx context.Context, tenantID string) (string, uint64, error) {
			authority, err := orchestrator.ResolveLiveTenantRegistrationAuthority(
				resolveCtx, d.Log, d.Store, tenantID)
			return authority.EventID, authority.EventSequence, err
		}); err != nil {
		return nil, fmt.Errorf("server: validate secret rotation scheduler startup authority: %w", err)
	}
	return proj, nil
}

func (s *Server) configureMutationSpine(
	ctx context.Context,
	d Deps,
	proj *projections.Projector,
) (*orchestrator.Orchestrator, *orchestrator.Idempotency, error) {
	if d.IdempotencyResultMigrator != nil {
		statuses, err := d.IdempotencyResultMigrator.MigrateAll(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("server: migrate historical idempotency results before readiness: %w", err)
		}
		if d.Logger != nil {
			var sealed int64
			for _, status := range statuses {
				sealed += status.SealedRowV1
			}
			d.Logger.Info("historical idempotency results satisfy tenant protection readiness",
				slog.Int("tenants", len(statuses)),
				slog.Int64("sealed_results", sealed),
			)
		}
	}
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
	orchOptions := historyRewriteOrchestratorOptions(d.Store, d.AuditSigningKey)
	orchOptions = append(orchOptions, orchestrator.WithProjector(proj))
	if d.EnableAgentChannel {
		orchOptions = append(orchOptions, orchestrator.WithClaimableAgentJobKinds(d.AgentClaimableJobKinds))
	}
	if d.OwnershipAttestationCadence > 0 {
		orchOptions = append(orchOptions, orchestrator.WithOwnershipAttestationCadence(d.OwnershipAttestationCadence))
	}
	if d.ConnectorRegistry != nil {
		// Stamp each connector side effect's per-row agent-role demand from the
		// shipped vantage census at enqueue (epic A3). Without a registry there
		// is nothing to classify against, and rows keep the empty demand.
		orchOptions = append(orchOptions,
			orchestrator.WithSideEffectRoleClassifier(connectorSideEffectRoleClassifier(d.ConnectorRegistry)))
	}
	idem := orchestrator.NewIdempotency(
		d.Store,
		orchestrator.WithResultProtector(d.IdempotencyResultProtector),
	)
	orchOptions = append(orchOptions, orchestrator.WithDurableIdempotency(idem))
	orch := orchestrator.NewOrchestrator(
		d.Log,
		d.Store,
		s.outbox,
		orchOptions...,
	)
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
	defaults := s.baseAPIOptions(d, ea)
	if d.AuditSigningKey != nil {
		defaults = append(defaults, api.WithPQCCampaignClosureSigner(d.AuditSigningKey))
	}
	if d.EnableRemediation {
		defaults = append(defaults,
			api.WithRemediation(),
		)
	}
	if d.LicensedAPIOptionsFactory != nil {
		licensedOpts, err := d.LicensedAPIOptionsFactory(LicensedAPIOptionsDeps{
			Store: d.Store, Log: d.Log, Outbox: s.outbox, SignerKeyStoreDir: d.SignerKeyStoreDir,
			KEMCustody: s.kemCustody(), TLSPostureDeployer: d.ConnectorRegistry,
			OutboxIntegrityKey: d.KEK,
			TenantCrypto:       d.TenantCrypto,
		})
		if err != nil {
			return nil, nil, err
		}
		defaults = append(defaults, licensedOpts...)
	}
	auditSvc := s.appendAuditAPIOptions(d, &defaults)
	if d.RateLimiter != nil {
		defaults = append(defaults, api.WithRateLimiter(d.RateLimiter))
	}
	if err := configureBreakglassAPIOptions(d, &defaults); err != nil {
		return nil, nil, err
	}
	defaults = append(defaults, api.WithPrivacyRetentionPolicy(d.PrivacyRetentionPolicy))
	defaults = append(defaults, api.WithPrivacyRetentionPolicySource(d.GovernancePolicySource))
	if err := s.configurePolicyGate(d, orch, &defaults); err != nil {
		return nil, nil, err
	}
	// configurePolicyGate initializes the server's real bulkhead set. Attach
	// operational read models only after that point so the Jobs and queues API
	// receives the live pool provider instead of permanently capturing the
	// truthful-but-wrong served=false fallback during startup.
	s.appendOperationalReadModels(d, &defaults)
	authOpt, err := buildBrowserAuth(d.OIDC, d.SAML, d.LDAP, d.SecurityHeaders.TLS, d.AuthHTTPClient, d.Store, d.KEK, d.TenantCrypto)
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
	// Effect-free review evidence is a platform primitive, not a native-secret-
	// store feature. Wire the KEK's keyed-digest seam even when that optional API
	// is disabled so F38 temporary access remains independently reviewable.
	if mac, ok := d.KEK.(secretCommandMAC); ok {
		defaults = append(defaults, api.WithCommandMAC(mac.KeyedDigest))
	}
	if d.EnableSecretsAPI {
		if d.KEK == nil {
			return nil, nil, errors.New("server: secrets API enabled but no KEK provided (envelope encryption at rest is required)")
		}
		defaults = append(defaults, api.WithSecrets(s.buildSecretsBackend(d)))
	}
	if err := s.appendTransitAPIOptions(d, &defaults); err != nil {
		return nil, nil, err
	}
	codeSigningConfig := d.CodeSigning
	if codeSigningConfig.Gate == nil {
		codeSigningConfig.Gate = s.codeSignGate
	}
	if cs, err := newServedCodeSigningService(codeSigningConfig, d.Store, d.Log, d.KEK, s.outbox, s.wakeOutbox, d.TenantCrypto); err != nil {
		return nil, nil, fmt.Errorf("server: configure code-signing: %w", err)
	} else if cs != nil {
		s.codeSign = cs
		defaults = append(defaults, api.WithCodeSigning(cs))
	}
	if d.Store != nil && d.Log != nil && s.outbox != nil {
		ctSubmit, err := newServedCTSubmissionService(d.Store, d.Log, s.outbox)
		if err != nil {
			return nil, nil, fmt.Errorf("server: configure CT submission: %w", err)
		}
		s.ctSubmit = ctSubmit
		defaults = append(defaults, api.WithCTSubmission(ctSubmit))
	}
	if hierarchySvc := s.buildCAHierarchyService(d); hierarchySvc != nil {
		s.caHierarchy, _ = hierarchySvc.(*caHierarchyService)
		defaults = append(defaults, api.WithCAHierarchy(hierarchySvc))
	}
	if edgeSvc := s.buildEdgeDelegationService(d, orch); edgeSvc != nil {
		defaults = append(defaults, api.WithEdgeDelegations(edgeSvc))
	}
	if externalCAs, err := s.buildExternalCAService(d, idem); err != nil {
		return nil, nil, err
	} else if externalCAs != nil {
		defaults = append(defaults, api.WithExternalCAs(externalCAs))
	}
	defaults = append(defaults, api.WithManagedKeyCustody(d.ManagedKeyCustody))
	s.appendProtocolQualificationOptions(d, &defaults)
	if mk, err := buildManagedKeyService(d, idem, s.outbox, orch); err != nil {
		return nil, nil, fmt.Errorf("server: configure managed-key lifecycle: %w", err)
	} else if mk != nil {
		defaults = append(defaults, api.WithManagedKeys(mk))
	}
	if d.EnableAISurface {
		defaults = append(defaults, api.WithAISurface(s.buildAISurfaceBackend(d)))
	}
	complianceAuditSvc := auditSvc
	if d.AuditSigningKey == nil {
		complianceAuditSvc = nil
	}
	if complianceSvc, err := s.buildComplianceEvidenceService(d, complianceAuditSvc); err != nil {
		return nil, nil, err
	} else if complianceSvc != nil {
		defaults = append(defaults, api.WithComplianceEvidence(complianceSvc))
	}
	// The Provider console is shipped in every web artifact, while its API is
	// attached only at the licensed EE seam. Publish that exact attachment bit
	// through the public auth bootstrap so the browser can fail closed without
	// probing the intentionally dark /provider/v1 namespace.
	defaults = append(defaults, api.WithProviderPlaneAvailable(d.ProviderHandler != nil))
	a := api.New(d.Store, idem, orch, append(defaults, d.APIOptions...)...)
	s.api = a
	return a, auditSvc, nil
}

// appendTransitAPIOptions keeps Transit service construction and its tenant-safe
// runtime posture reader together as one reviewable startup stage.
func (s *Server) appendTransitAPIOptions(d Deps, options *[]api.Option) error {
	transitSvc, err := s.buildTransitService(d)
	if err != nil {
		return err
	}
	if transitSvc != nil {
		*options = append(*options, api.WithTransit(transitSvc))
	}
	kmipEnabled := d.Protocols.KMIP.Enabled
	kmipTenantID := d.Protocols.KMIP.TenantID
	*options = append(*options, api.WithTransitPosture(func(_ context.Context, tenantID string) api.TransitRuntimePosture {
		return s.transitRuntimePosture(kmipEnabled, kmipTenantID, tenantID)
	}))
	return nil
}

// appendAuditAPIOptions keeps audit construction and its lazy TSA dependency in
// one named startup stage so configureAPI remains reviewable as features grow.
func (s *Server) appendAuditAPIOptions(d Deps, options *[]api.Option) *audit.Service {
	if d.Log == nil {
		return nil
	}
	auditSvc := audit.NewService(d.Log, d.AuditSigningKey, audit.WithCheckpoints(d.Store), audit.WithPrivacyErasures(d.Store))
	s.audit = auditSvc
	*options = append(*options, api.WithAudit(auditSvc))
	// J1: chain heads are countersigned by the served TSA. Resolved lazily —
	// the protocol mounts are built after this point.
	*options = append(*options, api.WithAuditTimestamper(auditTimestamper{srv: s}))
	return auditSvc
}

// appendProtocolQualificationOptions keeps the protocol readiness sources in
// one named startup stage instead of growing configureAPI for every protocol.
func (s *Server) appendProtocolQualificationOptions(d Deps, options *[]api.Option) {
	s.appendCMPQualificationOption(d, options)
	s.appendTSAQualificationOption(d, options)
	s.appendSPIFFEQualificationOption(d, options)
}

// baseAPIOptions is the always-on half of the served API surface: the options
// that do not depend on a licence, a flag, or a constructor that can fail.
// Named stage of configureAPI (startup-hotspot ratchet).
func (s *Server) baseAPIOptions(d Deps, ea enrollAuthority) []api.Option {
	return []api.Option{
		// J2: the DR posture surface reports on this directory. An empty value
		// is meaningful — the API then serves "not configured" rather than
		// reporting a path nobody chose as a missing backup.
		api.WithBackupDirectory(d.BackupDirectory),
		// J2: the last drill's attestation, or nil when none has run. The API
		// distinguishes the two; a zero attestation would read as a perfect one.
		api.WithRestoreDrill(s.LastRestoreDrill),
		api.WithRestoreDrillSigningKey(d.AuditSigningKey),
		api.WithAgentEnrollment(ea), api.WithAgentEnrollmentConnection(d.AgentChannelPublicAddress, d.AgentChannelServerName),
		api.WithAgentEnrollmentRenewal(d.EnableAgentChannel && s.agentCASigner != nil && len(s.agentCACertDER) > 0),
		api.WithAgentHeartbeatInterval(d.AgentHeartbeatInterval),
		api.WithAgentEnroller(ea), api.WithAgentEnrollmentObserver(s.observeAgentEnrollment),
		api.WithAttestedIssuer(s),
		api.WithSSHWorkflow(s),
		api.WithBroker(s),
		api.WithCertificateRevocationAuthority(s.certificateRevocationAuthority),
		api.WithEphemeralIssuer(s),
		api.WithPAM(s),
		api.WithEventLog(d.Log),
		api.WithLicense(d.License),
		api.WithFeatureObserver(s.featureMetrics.Hook()),
		api.WithCBOM(s.buildCBOMService(d)),
		api.WithNotificationChannels(notificationChannelNames(d.NotificationChannels)...),
		api.WithNotificationOutbox(s.outbox),
		api.WithServiceNowBindings(d.ServiceNowBindings...),
		api.WithOutboundEnvCredentialRefs(d.OutboundEnvCredentialRefs...),
		api.WithACMEDNS01CAAResolver(acme.DefaultCAAResolver()),
		api.WithACMEARIPosture(s.ACMEARIPosture),
		api.WithLifecycleAutomationPlan(s),
		api.WithTenantKeyDomainLifecycle(d.TenantKeyDomains),
		api.WithTenantCrypto(d.TenantCrypto),
		api.WithOwnershipAttestationCadence(d.OwnershipAttestationCadence),
	}
}

// appendOperationalReadModels attaches the read-only operator views (the B-1…B-6
// endpoints). Each is wired only when its provider exists, so an unwired
// subsystem answers "not served" rather than 404 — and none of them can mutate
// state. Named stage of configureAPI (startup-hotspot ratchet).
func (s *Server) appendOperationalReadModels(d Deps, defaults *[]api.Option) {
	if s.outbox != nil {
		*defaults = append(*defaults, api.WithOutboxCircuitStatus(s.outbox.CircuitStates))
	}
	// B-1: expose AN-7 pool pressure through the served API. The snapshot is
	// counters and subsystem names only — no tenant or credential data.
	if s.bulk != nil {
		*defaults = append(*defaults, api.WithBulkheadStats(s.bulk.Stats))
	}
	// B-4: signing operations joined to their transparency-log state.
	if d.Store != nil {
		*defaults = append(*defaults, api.WithCodeSigningIdentities(s.CodeSigningIdentities))
	}
	// B-2: the SSH fleet view over discovered standing keys.
	if d.Store != nil {
		*defaults = append(*defaults, api.WithSSHFleet(s.SSHFleetInventory))
	}
	// B-6: the connector catalog reports each connector's live sandbox grant
	// and replay contract from the registry, not from a description beside it.
	if s.connectorRegistry != nil {
		*defaults = append(*defaults, api.WithConnectorRegistry(s.connectorRegistry))
	}
	// H5: the CA console needs the same reference leaf validity the horizon
	// scheduler uses, so the "renew/re-key by" date it shows and the alert an
	// operator receives are answering the same question.
	*defaults = append(*defaults, api.WithCALeafValidity(s.lifecycleLeafValidity))
	// B4: the ACME external-account-binding operator surface. Read at request
	// time because protocol construction follows API construction, and because
	// the usage counters it exposes are live.
	*defaults = append(*defaults, api.WithACMEEAB(s.acmeEABPosture, s.setACMEEABDisabled))
	// F5: one effect-free, tenant-bound readiness/execute/recovery plan over the
	// late-bound ACME mount. This prevents the browser from inventing readiness
	// from a same-origin fetch that cannot see profile or EAB authority.
	*defaults = append(*defaults, api.WithACMEOperatorPlan(s.acmeOperatorPlan))
	// F69: preview and execute read the same late-bound provider/outbox/resolver
	// runtime used by served ACME orders. Attaching the Server pointer here is
	// safe even though protocol construction follows API construction.
	*defaults = append(*defaults, api.WithACMEDNS01Qualification(s))
	// A1: job-ledger queue depth and claim health, read at request time because
	// the counters are only useful fresh.
	*defaults = append(*defaults, api.WithAgentJobPosture(s.agentJobPosture))
	// D5/F27: target tests run at the deploy vantage. Host/network targets use an
	// explicitly enabled connector.test agent; cloud stores use the bounded
	// control-plane outbox worker. An unavailable agent path keeps the honest
	// local answer rather than queueing work nothing will claim.
	*defaults = append(*defaults, api.WithADCSPosture(s.adcsPostureView))
	*defaults = append(*defaults, api.WithADCSDrift(s.adcsDriftView))
	*defaults = append(*defaults, api.WithConnectorTestEnqueuer(
		s.connectorTestEnqueuer(AgentClaimableJobKinds(d.AgentClaimableJobKinds))))
	// B-5: the console's system readout reuses the same probes as /readyz, so
	// the two can never disagree about whether the spine can serve trustworthy
	// projected state.
	*defaults = append(*defaults, api.WithSystemReadout(func() api.SystemReadout {
		return s.systemReadout(context.Background())
	}))
	if d.Store != nil {
		*defaults = append(*defaults, api.WithIdempotencyResultProtection(
			idempotencyResultProtectionReadout(d.Store, d.IdempotencyResultFleetReady),
		))
	}
	if s.plugins != nil {
		*defaults = append(*defaults, api.WithACMEDNS01Providers(s.acmeDNS01PluginCatalog()...))
	}
}

func configureBreakglassAPIOptions(d Deps, defaults *[]api.Option) error {
	breakglassReconciler, err := buildBreakglassReconciler(d)
	if err != nil {
		return err
	}
	if breakglassReconciler != nil {
		*defaults = append(*defaults, api.WithBreakglass(breakglassReconciler))
	}
	breakglassIssuer, err := buildBreakglassIssuer(d, breakglassReconciler)
	if err != nil {
		return err
	}
	if breakglassIssuer != nil {
		*defaults = append(*defaults, api.WithBreakglassIssuer(breakglassIssuer))
	}
	if breakglassDependencyPresent(d.BreakglassCeremonies) {
		*defaults = append(*defaults, api.WithBreakglassCeremonies(d.BreakglassCeremonies))
	}
	if breakglassDependencyPresent(d.BreakglassRotation) {
		*defaults = append(*defaults, api.WithBreakglassRotation(d.BreakglassRotation))
	}
	return nil
}

func notificationChannelNames(channels []notify.Notifier) []string {
	names := make([]string, 0, len(channels))
	for _, ch := range channels {
		if ch == nil || ch.Name() == "" {
			continue
		}
		names = append(names, ch.Name())
	}
	return names
}

func (s *Server) buildTransitService(d Deps) (*transitpkg.Service, error) {
	if d.Log == nil {
		return nil, nil
	}
	s.transit = transitpkg.NewService(audit.NewAuditor(d.Log))
	// Durability for the transit keyring. Without it every key vanished on
	// restart and anything encrypted with it became permanently undecryptable —
	// a data-loss bug wearing the costume of a cache.
	//
	// Persistence needs the deployment KEK: key material is sealed at rest or it
	// is not written at all. NewStore returns nil when either the directory or
	// the wrapper is missing, so an unconfigured deployment keeps the old
	// in-memory behaviour rather than silently writing keys in the clear.
	s.transitStore = transitpkg.NewStore(d.TransitKeyringDir, d.KEK)
	if s.transitStore != nil {
		found, err := s.transitStore.HasState()
		if err != nil {
			return nil, fmt.Errorf("server: inspect sealed transit keyring: %w", err)
		}
		if err := s.transitStore.Load(s.transit); err != nil {
			// A keyring that EXISTS but cannot be opened must not be replaced by an
			// empty one and started anyway: the service would come up healthy,
			// mint fresh keys, and every existing ciphertext would silently become
			// undecryptable. Refusing to start is the recoverable failure — the
			// operator still has the sealed file and can fix the KEK.
			return nil, fmt.Errorf("server: open sealed transit keyring: %w", err)
		}
		s.transitStateMu.Lock()
		s.transitStateFound = found
		s.transitStateMu.Unlock()
	}
	if s.transitStore != nil {
		// Checkpoint after every create/rotate rather than relying on a periodic
		// flush: a key that works until the next restart and then silently does
		// not is exactly the failure this persistence exists to prevent.
		s.transit.SetPersist(func() error {
			if err := s.transitStore.Save(s.transit); err != nil {
				return err
			}
			s.transitStateMu.Lock()
			s.transitStateFound = true
			s.transitStateMu.Unlock()
			return nil
		})
	}
	return s.transit, nil
}

func (s *Server) transitRuntimePosture(kmipEnabled bool, kmipTenantID, tenantID string) api.TransitRuntimePosture {
	s.transitStateMu.RLock()
	stateFound := s.transitStateFound
	s.transitStateMu.RUnlock()
	s.kmipStateMu.RLock()
	listening := s.kmipListening
	s.kmipStateMu.RUnlock()
	tenantBound := kmipEnabled && strings.TrimSpace(kmipTenantID) != "" && kmipTenantID == tenantID
	address := ""
	if tenantBound && s.kmip != nil {
		address = s.kmip.Addr()
	}
	return api.TransitRuntimePosture{
		Served: s.transit != nil, PersistenceConfigured: s.transitStore != nil,
		SealedStateFound: stateFound, KMIPConfigured: tenantBound,
		KMIPServed: tenantBound && s.kmip != nil, KMIPListening: tenantBound && listening,
		KMIPTenantBound: tenantBound, KMIPAddress: address,
	}
}

// SaveTransitKeyring seals the current keyring. Callers invoke it after a key is
// created or rotated, so a restart between the mutation and the next checkpoint
// cannot lose the key that was just minted.
func (s *Server) SaveTransitKeyring() error {
	if s == nil || s.transitStore == nil {
		return nil
	}
	return s.transitStore.Save(s.transit)
}

func (s *Server) configurePolicyGate(d Deps, orch *orchestrator.Orchestrator, defaults *[]api.Option) error {
	s.bulk = d.Bulkhead
	if s.bulk == nil {
		s.bulk = bulkhead.Default()
	}
	// AN-7 for the signer round-trip itself: route every signer RPC through the
	// operator's bulkheads.signing pool. Without this hook the pool started,
	// --print-config and the support bundle echoed its limits back, and NOTHING
	// ever submitted work to it (AUD-6) — the operator's cap on concurrent
	// pressure against the isolated signer bound nothing. The submitted task is
	// waited on synchronously: Submit either queues it (bounded) or rejects fast
	// with the structured bulkhead error the caller can act on.
	if pool := s.bulk.Pool(bulkhead.SubsystemSigning); pool != nil {
		admit := func(call func() error) error {
			done := make(chan error, 1)
			if err := pool.Submit(func() { done <- call() }); err != nil {
				return err
			}
			return <-done
		}
		if setter, ok := d.Signer.(interface {
			SetAdmission(func(func() error) error)
		}); ok {
			setter.SetAdmission(admit)
		} else if d.Signer != nil && d.Signer.Client() != nil {
			d.Signer.Client().SetAdmission(admit)
		}
	}
	s.mBulkheads = observ.NewBulkheadMetrics(s.registry)
	gate, approvals, err := buildMutationGate(d, s.bulk, s.outbox, orch)
	if err != nil {
		return err
	}
	*defaults = append(*defaults, api.WithMutationGate(gate))
	s.codeSignGate = codeSigningGateFromMutationGate(gate)
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
	if d.Store != nil && d.Log != nil && s.outbox != nil {
		s.acmeDNS01 = newServedACMEDNS01Automation(d.Store, d.Log, s.outbox, d.KEK, s.plugins, d.TenantCrypto)
		// Close the late-binding seam: from here an ACME authority configured
		// with upstream_dns01 can actually publish challenge records (B7).
		d.UpstreamDV.set(s.acmeDNS01, d.Log)
	}
	if err := s.configureOutboxHandler(d, orch, idem, ensureCRL, publishCRL); err != nil {
		return err
	}
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
		if err := s.provisionCA(ctx, d.Signer.Client(), d.CACommonName, d.CACertFile, d.CAPublicCertFile); err != nil {
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

func (s *Server) configureOutboxHandler(d Deps, orch *orchestrator.Orchestrator, idem *orchestrator.Idempotency, ensureCRL, publishCRL func(context.Context, string) error) error {
	if len(d.NotificationChannels) > 0 || d.Store != nil {
		s.notifications = notify.NewDispatcher(d.NotificationChannels...)
		if d.Store != nil {
			s.notifications.SetPolicyResolver(notify.NewStorePolicyResolver(d.Store))
			s.notifications.SetChannelResolver(notify.NewStoreChannelResolver(d.Store))
			s.notifications.SetThresholdDedupLedger(notify.NewStoreThresholdDedupLedger(d.Store, d.Log))
			s.notifications.SetDeliveryReceiptLedger(notify.NewStoreDeliveryReceiptLedger(d.Store, d.Log))
		}
	}
	var licensed LicensedOutboxHandler
	if d.LicensedOutboxFactory != nil {
		var err error
		licensed, err = d.LicensedOutboxFactory(LicensedOutboxDeps{
			Store: d.Store, Log: d.Log, Idempotency: idem,
			IssueProtocolLeaf:  s.protocolLeafIssuer(d, orch, idem, ensureCRL, publishCRL),
			TLSPostureDeployer: d.ConnectorRegistry,
			OutboxIntegrityKey: d.KEK,
			TenantCrypto:       d.TenantCrypto,
			FeatureObserver:    s.featureObserver(),
			SignerKeyStoreDir:  d.SignerKeyStoreDir,
			Minter:             s.successionMinter(),
			IssuanceGate:       s.issuanceGate(),
			KEMCustody:         s.kemCustody(),
			ManagedKeyCustody:  s.managedKeyCustody(),
			GatedDestruction:   s.gatedDestruction(),
			Transit:            s.transit,
		})
		if err != nil {
			return err
		}
	}
	secretIntegrations := &secretIntegrationOutboxDispatcher{
		dynamicProviders:         d.TenantDynamicSecretProviders,
		fallbackDynamicProviders: d.DynamicSecretProviders,
		syncTargets:              d.TenantSecretSyncTargets,
		fallbackSyncTargets:      d.SecretSyncTargets,
		kek:                      d.KEK,
		tenantCrypto:             d.TenantCrypto,
		store:                    d.Store,
		log:                      d.Log,
	}
	var tenantKeyDomains *tenantKeyDomainSealOutboxDispatcher
	if d.TenantKeyDomains != nil {
		tenantKeyDomains = &tenantKeyDomainSealOutboxDispatcher{
			idem: idem, lifecycle: d.TenantKeyDomains,
		}
	}
	connectorPlugins := connectorPluginDeployerFromManager(s.plugins)
	var authorityIssue authorityIssueFunc
	if s.caHierarchy != nil {
		authorityIssue = s.caHierarchy.issueLeafForExactAuthority
	}
	switch {
	case s.obHandler != nil:
	case s.caSigner != nil:
		s.obHandler = &issuanceDispatcher{issue: s.IssueLeafWithProfile, authorityIssue: authorityIssue, chainPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caCertDER}), orch: orch, idem: idem, outbox: s.outbox, store: d.Store, audit: s.audit, admission: d.IssuanceAdmission, log: d.Log, defaultProfile: d.DefaultProfile, leafProfile: s.leafProfile, ensureCRL: ensureCRL, publishCRL: publishCRL, plugins: connectorPlugins, connectorRegistry: s.connectorRegistry, connectorRightSize: d.ConnectorRightSize, connectorPayloadKey: d.KEK, tenantCrypto: d.TenantCrypto, externalCAs: s.externalCAs, notifications: s.notifications, transparency: d.CodeSigning.TransparencyHandler, codeSign: s.codeSign, secretRepoScanner: secretScannerFromDeps(d), dns01: s.acmeDNS01, licensed: licensed, secretIntegrations: secretIntegrations, tenantKeyDomains: tenantKeyDomains}
	default:
		s.obHandler = &issuanceDispatcher{authorityIssue: authorityIssue, orch: orch, idem: idem, outbox: s.outbox, store: d.Store, audit: s.audit, admission: d.IssuanceAdmission, log: d.Log, plugins: connectorPlugins, connectorRegistry: s.connectorRegistry, connectorRightSize: d.ConnectorRightSize, connectorPayloadKey: d.KEK, tenantCrypto: d.TenantCrypto, externalCAs: s.externalCAs, notifications: s.notifications, transparency: d.CodeSigning.TransparencyHandler, codeSign: s.codeSign, secretRepoScanner: secretScannerFromDeps(d), dns01: s.acmeDNS01, licensed: licensed, secretIntegrations: secretIntegrations, tenantKeyDomains: tenantKeyDomains}
	}
	return nil
}

func (s *Server) featureObserver() func(feature, action, outcome string, seconds float64) {
	if s.featureMetrics == nil {
		return nil
	}
	return s.featureMetrics.Hook()
}

// successionMinter returns the out-of-process signer as a PCAS succession minter for
// the licensed-outbox seam (INT-04), or nil when no signer is configured — in which
// case a PCAS handler mints nothing and fails closed. The control plane never obtains
// key material: minting crosses the signer transport (claims 1/12/49).
func (s *Server) successionMinter() SuccessionMinter {
	if s.signer == nil {
		return nil
	}
	return s.signer.Client()
}

func (s *Server) managedKeyCustody() ManagedKeyCustody {
	if s.signer == nil {
		return nil
	}
	return s.signer.Client()
}

func (s *Server) gatedDestruction() GatedDestruction {
	if s.signer == nil {
		return nil
	}
	return s.signer.Client()
}

// issuanceGate returns the out-of-process signer as an AGID chain-bound issuance gate for
// the licensed-outbox seam (AGID-INT-WIRE), or nil when no signer is configured — in which
// case the AGID chain-bound path fails closed (brokerstore.ErrNoSignerGate) and mints
// nothing. The control plane never obtains key material: the gated issuance crosses the
// signer transport (the signer verifies the chain and mints inside the boundary; only
// public material returns).
func (s *Server) issuanceGate() IssuanceGate {
	if s.signer == nil {
		return nil
	}
	return s.signer.Client()
}

func (s *Server) kemCustody() KEMCustody {
	if s.signer == nil {
		return nil
	}
	return s.signer.Client()
}

func (s *Server) protocolLeafIssuer(d Deps, orch *orchestrator.Orchestrator, idem *orchestrator.Idempotency, ensureCRL, publishCRL func(context.Context, string) error) ProtocolLeafIssuer {
	return func(ctx context.Context, tenantID, protocol, idempotencyKey string, csrDER []byte) ([]byte, error) {
		issuer := &protocolIssuer{
			issue: s.IssueLeafWithProfile, issueLicensed: s.IssueLicensedLeafWithProfile,
			inspectLicensedCSR: s.licensedCSRInspector, parseLicensedCSR: s.licensedCSRParser,
			orch: orch, idem: idem, store: d.Store, log: d.Log, caID: IssuingCAID(),
			defaultProfile: d.DefaultProfile, leafProfile: s.leafProfile,
			ensureCRL: ensureCRL, publishCRL: publishCRL,
			tenantCrypto: d.TenantCrypto,
		}
		return issuer.IssueProtocolLeaf(ctx, tenantID, protocol, idempotencyKey, csrDER, protocolLeafTTL)
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
	profile, err := newEvalProtocolProfileControl(ctx, d.Protocols, protocols, d.Log)
	if err != nil {
		return err
	}
	s.protocolProfile = profile
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
		// Feature-neutral: forward the chain-bound issuance precondition the EE attach
		// seam may have set. Nil in Community / core-only, leaving the broker's
		// chain-bound seam inert and the free single-hop badge unaffected (INV-A10).
		IssuancePrecondition: d.BrokerIssuancePrecondition,
		TaskEnvelopeGate:     d.BrokerTaskEnvelopeGate,
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
	s.agentHTTPRenewalAddr = d.AgentHTTPRenewalAddr
	if s.agentHTTPRenewalAddr == "" {
		s.agentHTTPRenewalAddr = ":9444"
	}
	s.agentChannelServerName = d.AgentChannelServerName
	s.agentHeartbeatInterval = d.AgentHeartbeatInterval
	agentSvc := &agentService{
		store: d.Store, log: d.Log, orch: s.orch, idem: idem, caSigner: s.agentCASigner,
		caCertDER: s.agentCACertDER, beatInterval: d.AgentHeartbeatInterval,
		metrics: s.agentMetrics,
		// A1: nothing is claimable until an operator enables a kind AND an
		// agent-side executor for it exists. Empty is the honest default.
		claimableJobKinds: AgentClaimableJobKinds(d.AgentClaimableJobKinds),
		outbox:            s.outbox,
		// The redemption resolver seals with the SAME KEK and tenant custody the
		// issuance dispatcher sealed with — constructed from the same Deps, so
		// the two sides of the seal cannot drift apart (epic A3).
		relayCredentials: &relayCredentialResolver{store: d.Store, kek: d.KEK, tenantCrypto: d.TenantCrypto},
		// D5: an agent's dry-run plan becomes a delivery receipt an operator can
		// read on the Connectors page. Control-plane previews write the same
		// event-sourced receipt through the outbox dispatcher.
		recordDryRun:               s.dryRunReceipt,
		recordRollback:             s.rollbackReceipt,
		recordADCSInventory:        s.recordADCSInventory,
		recordRevocationHealth:     s.recordRevocationHealth,
		recordMigrationResult:      s.recordMigrationResult,
		recordCMDBSync:             s.recordCMDBSync,
		recordCMDBSyncFailure:      s.recordCMDBSyncFailure,
		recordMDMSync:              s.recordMDMSync,
		recordDiscoveryScan:        s.recordDiscoveryScan,
		recordTicketSync:           s.recordTicketSync,
		recordTicketSyncFailure:    s.recordTicketSyncFailure,
		recordEndpointVerification: s.recordEndpointVerificationSweep,
		recordDeployVerification:   s.recordDeployVerification,
		// B2: the CSR that comes back UP from a host-generated renewal is signed
		// through the SAME issuance dispatcher the control plane's own mints go
		// through, so the profile gate, the CA and the certificate record cannot
		// diverge for agent-originated requests.
		signSubjectCSR:      s.signAgentSubjectCSR,
		completeHostRenewal: s.completeHostRenewal,
		// B3: the Workload API moved to the hosts; this is the node API it calls.
		issueWorkloadSVID: s.issueWorkloadSVID,
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
		s.otlpAudit = otlp.NewAuditStreamer(d.Log, s.otlp)
	}
	s.tracer = observ.NewTracer(observ.CombineExporters(d.TraceExporter, s.otlp))
	s.mIdemPurged = s.registry.CounterVec("trstctl_idempotency_keys_purged_total", "Completed idempotency keys reclaimed by the retention sweep.", nil).WithLabelValues()
	s.mOutboxPurged = s.registry.CounterVec("trstctl_outbox_delivered_purged_total", "Delivered outbox rows reclaimed by the retention sweep.", nil).WithLabelValues()
	s.mProjLag = s.registry.Gauge("trstctl_projection_lag_events", "Number of events the read model is behind the head of the event log.")
	s.tailWorker = projections.NewTailWorker(d.Log, proj, s.mProjLag.Set, 0)
	s.mOutboxReconcileLag = s.registry.Gauge("trstctl_outbox_reconciliation_lag_events", "Number of events after the last boot reconciliation checkpoint.")
	s.mOutboxDeadLetter = s.registry.GaugeVec("trstctl_outbox_deadletter_depth", "Dead-lettered (permanently failed) outbox rows awaiting operator sweep or replay.", []string{"tenant_id", "destination"})
	s.outboxDeadLetterSeen = map[string][2]string{}
	s.mEventLogReplicasDesired = s.registry.Gauge("trstctl_event_log_replicas_desired", "Configured JetStream replica count required for the source-of-truth event stream.")
	s.mEventLogReplicasActual = s.registry.Gauge("trstctl_event_log_replicas_actual", "Observed JetStream replica count on the source-of-truth event stream.")
	s.mAgentsTotal = s.registry.Gauge("trstctl_agents_total", "Total agents currently known to the control plane.")
	s.mAgentsStale = s.registry.Gauge("trstctl_agents_stale_total", "Agents whose last heartbeat is older than two heartbeat intervals.")
	s.mApplicationSecretReconcileBlocked = s.registry.Gauge(
		"trstctl_application_secret_reconcile_blocked",
		"Durable application-secret commands whose crash recovery is blocked by tenant cryptographic custody.")
	s.mApplicationSecretReconcileDegraded = s.registry.Gauge(
		"trstctl_application_secret_reconcile_degraded",
		"Whether the most recent application-secret crash-recovery pass was custody-blocked or failed structurally (1 degraded, 0 healthy).")
	if s.api != nil {
		s.mApplicationSecretReconcileBlocked.Set(float64(s.api.ApplicationSecretMutationReconcileBlockedCount()))
		if s.api.ApplicationSecretMutationReconcileDegraded() {
			s.mApplicationSecretReconcileDegraded.Set(1)
		}
	}
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
	s.lifecycleLeafValidity = d.LifecycleLeafValidity
	s.ownershipAttestationCadence = d.OwnershipAttestationCadence
	s.lifecycleInterval = d.LifecycleInterval
	s.endpointVerificationInterval = d.EndpointVerificationInterval
	s.restoreDrill = d.RestoreDrill
	s.restoreDrillInterval = d.RestoreDrillInterval
	s.restoreDrillRPO = d.RestoreDrillRPO
	s.restoreDrillRTO = d.RestoreDrillRTO
	s.maintenanceWindows = d.MaintenanceWindows
	s.mLifecycleQueued = s.registry.CounterVec("trstctl_lifecycle_renewals_queued_total", "Identities queued by the lifecycle renewal scheduler.", nil).WithLabelValues()
	s.mLifecycleAlerts = s.registry.CounterVec("trstctl_lifecycle_expiry_alerts_queued_total", "Expiry notifications queued by the lifecycle scheduler.", nil).WithLabelValues()
	s.mLifecycleLastOK = s.registry.Gauge("trstctl_lifecycle_scheduler_last_success_timestamp_seconds", "Unix timestamp of the last successful lifecycle scheduler sweep.")
	s.mLifecycleFailures = s.registry.CounterVec("trstctl_lifecycle_scheduler_failures_total", "Lifecycle scheduler sweeps that failed.", nil).WithLabelValues()
	s.configureRetentionWorker(d, auditSvc)
	s.configurePrivacyRetentionWorker(d, orch)
	s.readiness = observ.NewReadiness(s.tracer, s.readinessChecks(ctx, d)...)
	if s.startedAt.IsZero() {
		s.startedAt = time.Now().UTC()
	}
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
	if auditSvc == nil || d.AuditSigningKey == nil || d.AuditRetention <= 0 || d.AuditArchiveDir == "" {
		return
	}
	s.retention = audit.NewRetentionWorker(auditSvc, d.Log, audit.DirArchiver{Dir: d.AuditArchiveDir}, d.Store, d.AuditRetention)
	s.mRetRuns = s.registry.CounterVec("trstctl_audit_retention_runs_total", "Audit retention runs that archived at least one segment.", nil).WithLabelValues()
	s.mRetArchived = s.registry.CounterVec("trstctl_audit_records_archived_total", "Audit records archived to cold storage by the retention worker.", nil).WithLabelValues()
	s.mRetPruned = s.registry.CounterVec("trstctl_audit_records_pruned_total", "Compatibility metric; always zero because logical audit retention never deletes the shared AN-2 source.", nil).WithLabelValues()
	s.mRetRetained = s.registry.CounterVec("trstctl_audit_source_records_retained_total", "Archived audit records whose AN-2 source envelopes were retained for rebuild and DR.", nil).WithLabelValues()
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
		{Name: "projection", Probe: s.probeProjectionTail},
		{Name: "secret_sync_recovery_authority", Probe: d.Store.RequireSecretSyncReceiverRecoveryAuthorized},
	}
	if s.api != nil {
		checks = append(checks, observ.Check{
			Name: "application_secret_reconciliation", Probe: s.api.ApplicationSecretMutationReconcileHealth,
		})
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
	consoleHandler := webui.Handler(webui.Assets())
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.readiness.Handler())
	mux.Handle("GET /metrics", s.metricsHandler())
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
	registerProtocolNamespaceFallbacks(mux, s.protocols)
	if d.ProviderHandler != nil {
		mux.Handle("/provider/", bulkheadHandler(s.bulk, bulkhead.SubsystemAPI, d.ProviderHandler))
	} else {
		mux.HandleFunc("/provider/", http.NotFound)
	}
	// Exact /provider is the provider console SPA entry. Its child namespace is
	// a separate API plane and remains dark unless the licensed handler above is
	// attached. Without this exact pattern net/http redirects /provider to
	// /provider/, where the API namespace correctly answers 404, making the
	// shipped provider console impossible to open in every edition.
	mux.Handle("/provider", consoleHandler)
	// Exact /ssh is the browser's SSH Trust workspace; only its children belong
	// to the SSH machine protocol. Registering /ssh/ for /ssh/ca and /ssh/krl
	// makes net/http redirect a bare /ssh to /ssh/ unless this exact pattern is
	// present. That redirect bypasses the SPA fallback and turns bookmarks and
	// refreshes into a protocol 404 even though in-app navigation works.
	mux.Handle("/ssh", consoleHandler)
	mux.Handle("/", consoleHandler)
	mw := observ.NewMiddleware(observ.Options{Logger: s.logger, Tracer: s.tracer, Registry: s.registry})
	s.agentHTTPRenewalHandler = securityHeadersMiddleware(d.SecurityHeaders, mw.Handler(bulkheadHandler(s.bulk, bulkhead.SubsystemAPI, a.AgentRenewalHandler())))
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
// When caPublicCertFile is set, the exact public certificate is also published
// there so a less-privileged client need not mount the private data volume.
func (s *Server) provisionCA(ctx context.Context, c *signing.Client, cn, caCertFile, caPublicCertFile string) error {
	if cn == "" {
		cn = "trstctl Issuing CA"
	}

	// Read public state before inspecting or generating the key. Malformed state
	// may be operator-recoverable, so never overwrite it and hide the damage.
	var persistedDER []byte
	if caCertFile != "" {
		pemBytes, err := os.ReadFile(caCertFile) // #nosec G304 -- operator-configured local file path from deployment config (CWE-22)
		if err == nil {
			blk, rest := pem.Decode(pemBytes)
			if blk == nil || blk.Type != "CERTIFICATE" || len(rest) != 0 {
				return fmt.Errorf("issuing CA certificate %q is invalid; refusing to overwrite it: restore the certificate that matches signer handle %q", caCertFile, issuingCAHandle)
			}
			persistedDER = blk.Bytes
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read issuing CA certificate %q: %w", caCertFile, err)
		}
	}

	// Reuse path: persisted cert + a signer that still has the exact CA key. Bind
	// the reloaded key to the CA-signing purpose so the signer's persisted per-key
	// constraint (SIGNER-002/003) is satisfied across a restart.
	remote, handleErr := s.signerForPrivilegedHandle(ctx, c, issuingCAHandle, signing.PurposeCASign)
	if handleErr == nil && len(persistedDER) > 0 {
		if err := crypto.VerifyCertificateSigner(persistedDER, remote.Public()); err != nil {
			return fmt.Errorf("issuing CA certificate %q does not match signer handle %q; refusing trust rotation: %w", caCertFile, issuingCAHandle, err)
		}
		s.caSigner = remote
		s.caCertDER = persistedDER
		return publishCAPublicCert(caCertFile, caPublicCertFile, persistedDER)
	}
	if handleErr != nil && status.Code(handleErr) != codes.NotFound {
		return fmt.Errorf("inspect signer-held issuing CA handle %q: %w", issuingCAHandle, handleErr)
	}
	if handleErr == nil {
		return fmt.Errorf("signer handle %q exists but issuing CA certificate %q is missing; refusing implicit trust replacement: restore the certificate or perform an explicit CA rotation", issuingCAHandle, caCertFile)
	}
	if len(persistedDER) > 0 {
		return fmt.Errorf("issuing CA certificate %q exists but signer handle %q is missing; refusing to generate a replacement key: restore signer custody or perform an explicit CA rotation", caCertFile, issuingCAHandle)
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
	return publishCAPublicCert(caCertFile, caPublicCertFile, caDER)
}

func publishCAPublicCert(caCertFile, caPublicCertFile string, caDER []byte) error {
	if caPublicCertFile == "" || (caCertFile != "" && filepath.Clean(caPublicCertFile) == filepath.Clean(caCertFile)) {
		return nil
	}
	if err := writeCertPEM(caPublicCertFile, caDER); err != nil {
		return fmt.Errorf("publish public CA cert: %w", err)
	}
	return nil
}

// writeCertPEM atomically writes a certificate (DER) PEM-encoded to path (0644 in
// a 0755 dir). The CA certificate is public, so it is not a secret. Atomic rename
// prevents a restart from observing a truncated trust anchor after a crash.
func writeCertPEM(path string, der []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- served CA certificate directory; the PEM is public material (CWE-276)
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*") // #nosec G304 -- same operator-configured directory as the target certificate (CWE-22)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o644); err != nil { // #nosec G306 -- served CA certificate PEM is public material (CWE-276)
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(pemBytes); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
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
	// A mathematically valid signature from an expired CA is still an unusable
	// credential. Make issuer-lifetime enforcement a property of the served
	// boundary, not an optional profile knob that a caller can forget to set.
	leafProfile.ClampTTLToIssuer = true
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

// IssueLicensedLeaf signs an end-entity certificate through a proprietary
// edition extension while keeping the CA signature in the out-of-process signer.
func (s *Server) IssueLicensedLeaf(ctx context.Context, csrDER []byte, ttl time.Duration) ([]byte, error) {
	return s.IssueLicensedLeafWithProfile(ctx, csrDER, ttl, s.leafProfile)
}

// IssueLicensedLeafWithProfile is IssueLicensedLeaf with an explicit served leaf
// profile, matching IssueLeafWithProfile for tenant profile enforcement.
func (s *Server) IssueLicensedLeafWithProfile(ctx context.Context, csrDER []byte, ttl time.Duration, leafProfile crypto.LeafProfile) ([]byte, error) {
	if s.caSigner == nil || s.caCertDER == nil {
		return nil, errors.New("server: licensed issuance unavailable — no out-of-process signer (fail closed)")
	}
	// Licensed algorithms share the same issuer-time boundary as core issuance.
	// The edition seam may change the leaf algorithm, never CA validity rules.
	leafProfile.ClampTTLToIssuer = true
	if s.licensedLeafSigner == nil {
		return nil, errors.New("server: licensed issuance unavailable — no licensed signer extension (fail closed)")
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
		der, err := s.licensedLeafSigner(s.caCertDER, s.caSigner, csrDER, ttl, leafProfile)
		ch <- result{der, err}
	}()
	select {
	case <-time.After(s.signTO):
		return nil, errors.New("server: signer timed out (fail closed)")
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("server: licensed issuance failed: %w", r.err)
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
	if s.protocols == nil || (s.protocols.activation != nil && !s.protocols.activation.Active()) {
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

// outboxDispatchFamily maps one disjoint destination family to its own bounded
// worker pool. The last entry is the compatibility/"other" lane: it excludes
// every named prefix, so one row can never be claimed by two family sweeps.
type outboxDispatchFamily struct {
	pool  string
	scope orchestrator.DestinationScope
}

var outboxDispatchFamilies = func() []outboxDispatchFamily {
	named := []outboxDispatchFamily{
		{pool: bulkhead.SubsystemOutboxExternalCA, scope: orchestrator.DestinationScope{IncludePrefixes: []string{"external-ca."}}},
		{pool: bulkhead.SubsystemOutboxConnectors, scope: orchestrator.DestinationScope{IncludePrefixes: []string{"connector."}}},
		{pool: bulkhead.SubsystemOutboxSecrets, scope: orchestrator.DestinationScope{IncludePrefixes: []string{"dynsecret."}}},
		{pool: bulkhead.SubsystemOutboxSecretSync, scope: orchestrator.DestinationScope{IncludePrefixes: []string{"secret.sync"}}},
		{pool: bulkhead.SubsystemOutboxManagedKeys, scope: orchestrator.DestinationScope{IncludePrefixes: []string{"managedkey."}}},
		{pool: bulkhead.SubsystemOutboxTransparency, scope: orchestrator.DestinationScope{IncludePrefixes: []string{"transparency."}}},
		{pool: bulkhead.SubsystemOutboxCodeSigning, scope: orchestrator.DestinationScope{IncludePrefixes: []string{"codesign."}}},
		{pool: bulkhead.SubsystemOutboxNotifications, scope: orchestrator.DestinationScope{IncludePrefixes: []string{"notification."}}},
		{pool: bulkhead.SubsystemOutboxTenantSeal, scope: orchestrator.DestinationScope{IncludePrefixes: []string{store.TenantKeyDomainSealDestination}}},
		{pool: bulkhead.SubsystemOutboxFleet, scope: orchestrator.DestinationScope{IncludePrefixes: []string{"incident.fleet_reissuance."}}},
		{pool: bulkhead.SubsystemOutboxAuditFeeds, scope: orchestrator.DestinationScope{IncludePrefixes: []string{"audit.feed."}}},
	}
	excluded := make([]string, 0, 8)
	for _, family := range named {
		excluded = append(excluded, family.scope.IncludePrefixes...)
	}
	return append(named, outboxDispatchFamily{
		pool:  bulkhead.SubsystemOutbox,
		scope: orchestrator.DestinationScope{ExcludePrefixes: excluded},
	})
}()

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
		case <-s.outboxWake:
			s.dispatchOnce(ctx)
		}
	}
}

// wakeOutbox asks the normal bounded dispatcher worker to sweep promptly after a
// request persists new outbox work. It never performs delivery on the request
// goroutine, and the single buffered signal coalesces bursts without backpressure.
func (s *Server) wakeOutbox() {
	if s == nil || s.outboxWake == nil {
		return
	}
	select {
	case s.outboxWake <- struct{}{}:
	default:
	}
}

// dispatchOnce submits one scoped sweep per external-effect family. Each family
// has its own bounded worker pool, so blocked connector calls shed only connector
// ticks while external-CA, secret, managed-key, transparency/code-signing,
// notification, and unrelated work keep moving (AN-7). Concurrent sweeps are safe
// because the scopes are disjoint and claims use FOR UPDATE SKIP LOCKED.
//
// Older embedded compositions and focused tests may provide only the legacy
// SubsystemOutbox pool. In that case retain the old one-task/unscoped behavior;
// production Configs always installs every family pool.
func (s *Server) dispatchOnce(ctx context.Context) {
	if !s.hasOutboxFamilyPool() {
		run := func() { _, _ = s.outbox.Dispatch(ctx, s.obHandler) }
		if s.bulk == nil || s.bulk.Pool(bulkhead.SubsystemOutbox) == nil {
			run()
			return
		}
		_ = s.bulk.Submit(bulkhead.SubsystemOutbox, run)
		return
	}

	for _, family := range outboxDispatchFamilies {
		family := family
		for range s.outboxFamilyConcurrency(family) {
			run := func() { _, _ = s.outbox.DispatchScoped(ctx, s.obHandler, family.scope) }
			pool := family.pool
			if s.bulk.Pool(pool) == nil {
				pool = bulkhead.SubsystemOutbox
			}
			if s.bulk.Pool(pool) == nil {
				run()
				continue
			}
			_ = s.bulk.Submit(pool, run)
		}
	}
}

// outboxFamilyConcurrency is the single source of truth for live and shutdown
// delivery fan-out. Deployment configuration may set a family to one worker; a
// hard-coded sweep count would silently bypass that receiver's AN-7 limit during
// Drain. Missing family pools inherit the compatibility outbox pool, and a
// pool-less focused composition remains serial.
func (s *Server) outboxFamilyConcurrency(family outboxDispatchFamily) int {
	if s == nil || s.bulk == nil {
		return 1
	}
	pool := s.bulk.Pool(family.pool)
	if pool == nil {
		pool = s.bulk.Pool(bulkhead.SubsystemOutbox)
	}
	if pool == nil {
		return 1
	}
	workers := pool.Stats().Workers
	if workers < 1 {
		return 1
	}
	return workers
}

func (s *Server) hasOutboxFamilyPool() bool {
	if s.bulk == nil {
		return false
	}
	for _, family := range outboxDispatchFamilies[:len(outboxDispatchFamilies)-1] {
		if s.bulk.Pool(family.pool) != nil {
			return true
		}
	}
	return false
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

// applicationSecretReconcileInterval bounds how long a tenant custody recovery
// can remain unnoticed after startup. The sweep is metadata/ciphertext-only and
// serialized inside the API; a tenant outage cannot block another tenant's pass.
const applicationSecretReconcileInterval = 15 * time.Second

// RunApplicationSecretMutationReconciler periodically retries durable commands
// stranded by a process crash. Custody-unavailable commands remain fenced and
// degrade readiness; structural store/event-log failures are logged and retried.
func (s *Server) RunApplicationSecretMutationReconciler(ctx context.Context) {
	if s.api == nil {
		return
	}
	s.reconcileApplicationSecretMutationsOnce(ctx)
	ticker := time.NewTicker(applicationSecretReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reconcileApplicationSecretMutationsOnce(ctx)
		}
	}
}

func (s *Server) reconcileApplicationSecretMutationsOnce(ctx context.Context) {
	healed, err := s.api.ReconcileApplicationSecretMutationFences(ctx)
	if s.mApplicationSecretReconcileBlocked != nil {
		s.mApplicationSecretReconcileBlocked.Set(float64(s.api.ApplicationSecretMutationReconcileBlockedCount()))
	}
	if s.mApplicationSecretReconcileDegraded != nil {
		degraded := 0.0
		if s.api.ApplicationSecretMutationReconcileDegraded() {
			degraded = 1
		}
		s.mApplicationSecretReconcileDegraded.Set(degraded)
	}
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("application-secret crash recovery sweep incomplete",
				slog.Int("blocked", s.api.ApplicationSecretMutationReconcileBlockedCount()),
				slog.String("error", err.Error()))
		}
		return
	}
	if healed > 0 && s.logger != nil {
		s.logger.Info("application-secret crash recovery sweep completed commands", slog.Int("healed", healed))
	}
}

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
// keeps the projection-lag gauge current. The worker is submitted to the
// projections bulkhead (SPINE-005), so the advertised projection worker/queue
// knobs bound ownership of the served tail instead of being documentation-only
// capacity. A tail error (e.g. a poison event leaving the durable cursor stuck) is
// logged and the loop re-enters after a short backoff; the lag gauge plateaus,
// which is the operator's divergence signal. It is meant to run in its own
// goroutine.
func (s *Server) RunProjectionTail(ctx context.Context) {
	if s.tailWorker == nil {
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		if err := s.runProjectionTailOnce(ctx); err != nil && ctx.Err() == nil {
			msg := "projection tail worker stopped; retrying"
			if errors.Is(err, bulkhead.ErrRejected) {
				msg = "projection tail bulkhead saturated; retrying"
			}
			s.logger.Warn(msg, slog.String("error", err.Error()))
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}
}

func (s *Server) runProjectionTailOnce(ctx context.Context) error {
	if s.bulk == nil || s.bulk.Pool(bulkhead.SubsystemProjections) == nil {
		return s.tailWorker.Run(ctx)
	}

	errCh := make(chan error, 1)
	if err := s.bulk.Submit(bulkhead.SubsystemProjections, func() {
		errCh <- s.tailWorker.Run(ctx)
	}); err != nil {
		return err
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
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
	if sampleErr := s.sampleOutboxDeadLetterDepth(ctx); sampleErr != nil && err == nil {
		err = sampleErr
	}
	return err
}

// sampleOutboxDeadLetterDepth refreshes the per-tenant/destination dead-letter
// gauge (OPS-DLQ-001). Buckets that drained since the last sample are zeroed so
// the alert clears when an operator sweeps or replays the rows.
func (s *Server) sampleOutboxDeadLetterDepth(ctx context.Context) error {
	if s.store == nil || s.mOutboxDeadLetter == nil {
		return nil
	}
	depths, err := s.store.OutboxDeadLetterDepth(ctx)
	if err != nil {
		return err
	}
	current := map[string][2]string{}
	for _, d := range depths {
		key := d.TenantID + "\x1f" + d.Destination
		current[key] = [2]string{d.TenantID, d.Destination}
		s.mOutboxDeadLetter.WithLabelValues(d.TenantID, d.Destination).Set(float64(d.Depth))
	}
	for key, labels := range s.outboxDeadLetterSeen {
		if _, ok := current[key]; !ok {
			s.mOutboxDeadLetter.WithLabelValues(labels[0], labels[1]).Set(0)
		}
	}
	s.outboxDeadLetterSeen = current
	return nil
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

const (
	defaultLifecycleSchedulerInterval  = time.Minute
	lifecycleARIRenewalReasonPrefix    = "scheduled renewal from ARI window "
	lifecycleFixedRenewalReasonPrefix  = "scheduled renewal before "
	lifecycleTransitionOriginScheduler = "lifecycle_scheduler"
)

// RunLifecycleScheduler runs the leader-only certificate renewal scheduler until
// ctx is cancelled (JOURNEY-002/F6/NOTIF-01). It does not sign certificates or send
// notifications directly. It scans deployed X.509 identities with active served
// certificates expiring within the configured renewal window and queues the normal
// deployed->renewing lifecycle transition; the outbox then mints the successor
// through ca.renew. It also scans active certificates inside the alert window and
// queues notification.expiry rows; the outbox then fans them to configured notify
// channels. A sweep error is logged and the next tick retries.
func (s *Server) RunLifecycleScheduler(ctx context.Context) {
	if (s.lifecycleRenewBefore <= 0 && s.lifecycleAlertBefore <= 0 && s.ownershipAttestationCadence <= 0) || s.orch == nil || s.store == nil {
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
	if (s.lifecycleRenewBefore <= 0 && s.lifecycleAlertBefore <= 0 && s.ownershipAttestationCadence <= 0) || s.orch == nil || s.store == nil {
		return 0, nil
	}
	now := time.Now().UTC()
	queued := 0
	if s.lifecycleRenewBefore > 0 {
		// D6: a closed maintenance window DEFERS renewals, it never drops them.
		//
		// The deferral is recorded rather than silent. A change freeze that
		// quietly stopped renewals would look exactly like a scheduler working
		// correctly, right up until certificates started expiring — and expiry
		// is the more expensive of the two failures by a wide margin. An
		// operator has to be able to see that work is being held and when it
		// will resume.
		if reason := s.maintenanceWindows.DeferralReason(now); reason != "" {
			s.recordRenewalDeferral(ctx, now, reason)
		} else {
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
					payload, err := json.Marshal(transitionTrigger{
						IdentityID:             ident.ID,
						To:                     string(orchestrator.StateRenewing),
						Reason:                 reason,
						Origin:                 lifecycleTransitionOriginScheduler,
						PredecessorFingerprint: candidate.Certificate.Fingerprint,
					})
					if err != nil {
						s.observeLifecycleSweep(queued, 0, err)
						return queued, err
					}
					if err := s.orch.TransitionWithSideEffectPayload(ctx, tenant, ident.ID, orchestrator.StateRenewing, reason, payload); err != nil {
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
	}
	alerted, err := s.runLifecycleAlertsOnce(ctx)
	if err != nil {
		s.observeLifecycleSweep(queued, alerted, err)
		return queued, err
	}
	// The CA calendar runs on the same sweep but its own clock: leaf expiry is
	// measured in days, a trust anchor's in months (H5). Its alerts count toward
	// the same metric so a stalled horizon sweep is as visible as a stalled leaf
	// sweep.
	horizonAlerts, err := s.runCAHorizonAlertsOnce(ctx)
	if err != nil {
		s.observeLifecycleSweep(queued, alerted+horizonAlerts, err)
		return queued, err
	}
	ownershipAlerts, err := s.runOwnershipReattestationOnce(ctx)
	if err != nil {
		s.observeLifecycleSweep(queued, alerted+horizonAlerts+ownershipAlerts, err)
		return queued, err
	}
	s.observeLifecycleSweep(queued, alerted+horizonAlerts+ownershipAlerts, nil)
	return queued, nil
}

// runOwnershipReattestationOnce is bounded twice: tenant discovery selects only
// due owners and each tenant page is capped. QueueOwnershipReattestation repeats
// the predicate under a row lock, so two leader replicas racing one sweep still
// append and enqueue one immutable request per verification edge.
func (s *Server) runOwnershipReattestationOnce(ctx context.Context) (int, error) {
	if s.ownershipAttestationCadence <= 0 || s.store == nil || s.orch == nil || s.outbox == nil {
		return 0, nil
	}
	now := time.Now().UTC()
	tenants, err := s.store.TenantsWithOwnershipReattestationCandidates(ctx, now, s.ownershipAttestationCadence)
	if err != nil {
		return 0, err
	}
	queued := 0
	for _, tenantID := range tenants {
		owners, err := s.store.ListOwnershipReattestationCandidates(ctx, tenantID, now, s.ownershipAttestationCadence, 200)
		if err != nil {
			return queued, err
		}
		for _, owner := range owners {
			inserted, err := s.orch.QueueOwnershipReattestation(ctx, tenantID, owner.ID, s.ownershipAttestationCadence)
			if err != nil {
				return queued, err
			}
			if inserted {
				queued++
			}
		}
	}
	return queued, nil
}

// runCAHorizonAlertsOnce sweeps every tenant's CA authorities for year-scale
// expiry horizons and leaf-validity compression. Unlike leaf expiry alerting it
// has no configurable window to switch it off: an expiring root is not an
// operator preference, and the thresholds are policy in internal/lifecycle.
func (s *Server) runCAHorizonAlertsOnce(ctx context.Context) (int, error) {
	if s.notifications == nil || s.store == nil || s.outbox == nil || s.log == nil {
		return 0, nil
	}
	tenants, err := s.store.TenantsWithCAHorizonCandidates(ctx)
	if err != nil {
		return 0, err
	}
	m := lifecycle.NewManager(s.store, nil, s.outbox, s.idem, s.log, lifecycle.Config{LeafValidity: s.lifecycleLeafValidity})
	alerted := 0
	for _, tenant := range tenants {
		n, err := m.AlertCAHorizon(ctx, tenant)
		if err != nil {
			return alerted, err
		}
		alerted += n
	}
	return alerted, nil
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
			return fmt.Sprintf(lifecycleARIRenewalReasonPrefix+"%s..%s",
				info.SuggestedWindow.Start.Format(time.RFC3339),
				info.SuggestedWindow.End.Format(time.RFC3339)), true
		}
	}
	if notAfter.Before(fixedCutoff) {
		return lifecycleFixedRenewalReasonPrefix + fixedCutoff.Format(time.RFC3339), true
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

func (s *Server) sampleBulkheads() {
	if s.mBulkheads == nil || s.bulk == nil {
		return
	}
	s.mBulkheads.Observe(s.bulk.Stats())
}

func (s *Server) metricsHandler() http.Handler {
	registryHandler := s.registry.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.sampleBulkheads()
		registryHandler.ServeHTTP(w, r)
	})
}

// RunRetentionOnce performs one audit retention pass and records its outcome as
// metrics. It is exported so the assembled server can be driven through a single
// archive/checkpoint cycle in tests. A nil worker (retention not configured) is a
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
		s.mRetRetained.Add(float64(sum.RecordsSourceRetained))
		if sum.SegmentsArchived > 0 {
			s.mRetRuns.Inc()
		}
	}
	if sum.RecordsArchived > 0 {
		s.logger.Info("audit retention archived records and retained AN-2 source envelopes",
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

// DispatchIssuanceOnce attempts one pending command owned by the built-in CA
// issuance lane. A live diagnostic creates one durable command and calls this
// once, so its latency includes claim, signer-backed delivery, and durable
// finalization, but not a second empty-queue shutdown sweep. External-CA issuance
// and every unrelated effect family are deliberately excluded.
func (s *Server) DispatchIssuanceOnce(ctx context.Context) (bool, error) {
	if s == nil || s.outbox == nil || s.obHandler == nil {
		return false, errors.New("server: issuance dispatcher is unavailable")
	}
	scope := orchestrator.DestinationScope{IncludePrefixes: []string{"ca.issue"}}
	return s.outbox.DispatchOneScoped(ctx, s.obHandler, scope)
}

// Drain delivers pending outbox entries through the configured handler. Families
// sweep concurrently during shutdown as well: a slow connector cannot delay the
// final notification or external-CA sweep until its own family deadline expires.
// Each DispatchScoped call still delivers serially within its family and preserves
// tenant/destination fairness, leases, delivery timeouts, and terminal callbacks.
// A legacy composition with no family pools keeps its historical serial drain.
func (s *Server) Drain(ctx context.Context) error {
	if !s.hasOutboxFamilyPool() {
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

	// Each family keeps sweeping independently until every worker is quiet at
	// the same time. A barrier-per-round deadlocks a parent effect that durably
	// creates work for another family and waits for its result: the child
	// family's first sweep may finish just before the parent enqueues, then sit
	// behind the barrier while the parent waits. External-CA-backed lifecycle
	// issuance is exactly that shape (ca.issue -> external-ca.issue).
	type drainWorkerState struct {
		initialized bool
		busy        bool
		lastN       int
		err         error
	}
	drainCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	states := make([]drainWorkerState, 0)
	for _, family := range outboxDispatchFamilies {
		for range s.outboxFamilyConcurrency(family) {
			states = append(states, drainWorkerState{})
		}
	}
	var (
		stateMu sync.Mutex
		wg      sync.WaitGroup
		index   int
	)
	for _, family := range outboxDispatchFamilies {
		family := family
		for range s.outboxFamilyConcurrency(family) {
			workerIndex := index
			index++
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					stateMu.Lock()
					states[workerIndex].busy = true
					stateMu.Unlock()
					n, err := s.outbox.DispatchScoped(drainCtx, s.obHandler, family.scope)
					stateMu.Lock()
					states[workerIndex] = drainWorkerState{initialized: true, lastN: n, err: err}
					stateMu.Unlock()
					if err != nil || drainCtx.Err() != nil {
						return
					}
					if n == 0 {
						timer := time.NewTimer(25 * time.Millisecond)
						select {
						case <-drainCtx.Done():
							if !timer.Stop() {
								<-timer.C
							}
							return
						case <-timer.C:
						}
					}
				}
			}()
		}
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	quietChecks := 0
	for {
		select {
		case <-ctx.Done():
			cancel()
			wg.Wait()
			return ctx.Err()
		case <-ticker.C:
			stateMu.Lock()
			allQuiet := len(states) > 0
			var dispatchErr error
			for _, state := range states {
				dispatchErr = errors.Join(dispatchErr, state.err)
				if !state.initialized || state.busy || state.lastN != 0 {
					allQuiet = false
				}
			}
			stateMu.Unlock()
			if dispatchErr != nil {
				cancel()
				wg.Wait()
				return dispatchErr
			}
			if allQuiet {
				quietChecks++
			} else {
				quietChecks = 0
			}
			if quietChecks >= 2 {
				cancel()
				wg.Wait()
				return nil
			}
		}
	}
}

// Shutdown drains the subsystem pools and the outbox, then closes the event log
// and datastore in order — the graceful drain that completes in-flight work
// without loss (R2.3 / AN-7).
func (s *Server) Shutdown(ctx context.Context) error {
	var errs []error
	// Drain the outbox BEFORE closing the pools, not after.
	//
	// Pool.Close does more than stop accepting work: it closes the queue and waits
	// for workers, after which every Submit returns ReasonClosed. Every signer call
	// goes through the signing pool's admission hook, so closing first meant the
	// final sweep could not sign — a queued certificate, a CRL, an OCSP response
	// would fail during the graceful shutdown that exists to complete them.
	//
	// Nothing new can arrive in the meantime: serveRuntime shuts the HTTP server
	// down and waits for in-flight handlers before calling this, so the drain has
	// the pools to itself. Closing them after the sweep still satisfies the AN-7
	// graceful drain — it just does the draining first, which is the order the
	// comment here always claimed.
	if err := s.Drain(ctx); err != nil {
		errs = append(errs, fmt.Errorf("drain outbox: %w", err))
	}
	if s.bulk != nil {
		s.bulk.Close()
	}
	if s.notifications != nil {
		s.notifications.Close()
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
	if s.protocols != nil {
		s.protocols.Close()
	}
	if s.kmip != nil {
		s.kmip.Close()
	}
	if s.complianceSigner != nil {
		s.complianceSigner.Destroy()
	}
	if s.cloudTokenMinter != nil {
		s.cloudTokenMinter.Close()
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

// recordRenewalDeferral records that a sweep was held by a maintenance window
// (epic D6).
//
// An event rather than a log line, because the question an operator asks is
// "why has nothing renewed since Friday" and a log line is not where they will
// look. The reason names when the window next opens, so the answer is
// actionable rather than merely true.
//
// Deliberately at most one per sweep rather than one per deferred certificate:
// a freeze holds the whole sweep, and a thousand events saying the same thing
// would bury the one that matters.
func (s *Server) recordRenewalDeferral(ctx context.Context, now time.Time, reason string) {
	if s.log == nil || s.store == nil {
		return
	}
	// The deferral is a system-wide fact, so it is recorded once per tenant
	// that had work to hold — a tenant with nothing due does not need telling
	// that nothing happened.
	tenants, err := s.store.TenantsWithRenewalIdentityCandidates(ctx, now.Add(s.lifecycleRenewBefore), now)
	if err != nil {
		return
	}
	for _, tenant := range tenants {
		payload, merr := json.Marshal(map[string]any{
			"reason":      reason,
			"deferred_at": now.UTC(),
			"window_open": s.maintenanceWindows.NextOpen(now).UTC(),
		})
		if merr != nil {
			continue
		}
		_, _ = s.log.Append(ctx, events.Event{
			Type: "lifecycle.renewal.deferred", TenantID: tenant, Data: payload,
		})
	}
}
