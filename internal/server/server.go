// Package server is the composition root of the trustctl control plane (S7.7): it
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

	"trustctl.io/trustctl/internal/agent/enroll"
	"trustctl.io/trustctl/internal/api"
	"trustctl.io/trustctl/internal/audit"
	"trustctl.io/trustctl/internal/bulkhead"
	"trustctl.io/trustctl/internal/config"
	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/crypto/jose"
	"trustctl.io/trustctl/internal/events"
	"trustctl.io/trustctl/internal/idemgc"
	"trustctl.io/trustctl/internal/observ"
	"trustctl.io/trustctl/internal/orchestrator"
	"trustctl.io/trustctl/internal/outboxgc"
	"trustctl.io/trustctl/internal/projections"
	"trustctl.io/trustctl/internal/protocols/acme"
	"trustctl.io/trustctl/internal/signing"
	"trustctl.io/trustctl/internal/store"
	"trustctl.io/trustctl/internal/webui"
)

// SignerProvider yields the current connected signer client, or nil when no
// signer is healthy. The signing.Supervisor satisfies it.
type SignerProvider interface {
	Client() *signing.Client
}

// Deps are the wired dependencies of the serving control plane. Tests inject an
// embedded store/log and an in-process signer; production wires the real ones.
type Deps struct {
	Store          *store.Store
	Log            *events.Log
	Signer         SignerProvider       // may be nil → issuance is unavailable (fail closed)
	OutboxHandler  orchestrator.Handler // delivers outbox entries; defaults to a no-op success
	APIOptions     []api.Option         // auth/audit/etc.
	SignTimeout    time.Duration        // per-issuance signer deadline (slow → fail closed)
	CACommonName   string
	CACertFile     string             // persisted issuing-CA cert path; reused across restarts so the CA is stable (R3.2)
	LeafProfile    crypto.LeafProfile // served-leaf RFC 5280/BR profile: CDP/AIA/policy + constraints (PKIGOV-001/002)
	DefaultProfile string             // certificate-profile name enforced on the served mint when it resolves (PKIGOV-002); empty = none
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
	AuditRetention    time.Duration    // audit retention window (R4.4); >0 with AuditArchiveDir enables the retention worker
	AuditArchiveDir   string           // cold-storage directory for signed audit archive bundles (R4.4)
	// IdempotencyRetention bounds how long a completed idempotency key is kept
	// before the background GC sweep reclaims it (SPINE-002). Zero uses
	// idemgc.DefaultRetention. AN-5 holds within the window.
	IdempotencyRetention time.Duration
	// OutboxRetention bounds how long a delivered outbox row is kept before the
	// background purge sweep reclaims it (SPINE-003). Zero uses
	// outboxgc.DefaultRetention. At-least-once delivery (AN-6) is unaffected — only
	// already-delivered rows are reclaimed.
	OutboxRetention time.Duration
	Logger          *slog.Logger    // structured access log sink (R2.2); nil discards
	TraceExporter   observ.Exporter // completed-span sink (R2.2); nil is a no-op
	Bulkhead        *bulkhead.Set   // per-subsystem bounded pools (R2.3/AN-7); nil uses bulkhead.Default()
	RateLimiter     api.RateLimiter // per-tenant rate limiter (R2.3); nil disables rate limiting
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
	// AuthHTTPClient performs the OIDC code→token exchange. Production leaves it nil
	// (a default 10s client). The end-to-end acceptance test injects a client that can
	// reach a loopback mock IdP, without weakening the production default.
	AuthHTTPClient *http.Client
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

	signer    SignerProvider
	caSigner  crypto.DigestSigner // a *signing.RemoteSigner — the CA key lives in the signer
	caCertDER []byte
	signTO    time.Duration

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
	// protoRACertDER / protoRAKeyPKCS8 are the in-process RSA transport key+cert
	// SCEP/CMP use for CMS transport (AN-4: NOT the CA key, which stays in the
	// signer). Memoized so SCEP and CMP share one transport key per process.
	protoRACertDER  []byte
	protoRAKeyPKCS8 []byte

	// leafProfile is the served issuing CA's RFC 5280 / BR profile (PKIGOV-001):
	// CDP/AIA/policy pointers and key/EKU/validity constraints stamped on every leaf
	// the served path mints. The zero value preserves the legacy leaf shape (plus an
	// always-present Subject Key Identifier).
	leafProfile crypto.LeafProfile

	logger    *slog.Logger
	registry  *observ.Registry
	tracer    *observ.Tracer
	readiness *observ.Readiness
	bulk      *bulkhead.Set

	// Audit retention worker (R4.4); nil unless retention + archive are configured.
	retention    *audit.RetentionWorker
	mRetRuns     *observ.Counter
	mRetArchived *observ.Counter
	mRetPruned   *observ.Counter

	// Signer telemetry (SF.3): the out-of-process signer can't serve its own
	// /metrics (AN-4), so the control plane samples its health/restarts here.
	mSigner *observ.SignerMetrics

	// Idempotency-key GC telemetry (SPINE-002): rows reclaimed by the sweep.
	mIdemPurged *observ.Counter

	// Outbox GC telemetry (SPINE-003): delivered rows reclaimed by the purge sweep.
	mOutboxPurged *observ.Counter

	// Tailing projection worker + lag gauge (SPINE-009): a durable consumer that
	// projects events appended out of band and surfaces projection lag.
	tailWorker *projections.TailWorker
	mProjLag   *observ.Gauge

	// CRL freshness scheduler telemetry (EXC-REVOKE-01): CRLs regenerated by the
	// background freshness sweep, so the served CRL's freshness is observable.
	mCRLRegen *observ.Counter
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
	s := &Server{
		store:       d.Store,
		log:         d.Log,
		signer:      d.Signer,
		signTO:      d.SignTimeout,
		obHandler:   d.OutboxHandler,
		leafProfile: d.LeafProfile,
	}
	if s.signTO <= 0 {
		s.signTO = 10 * time.Second
	}

	// 1) Read model catches up from the event log (AN-2): the relational state is
	// a projection, so we replay before serving reads. The catch-up resumes from the
	// persisted projection checkpoint (SPINE-007) and replays only the tail after it,
	// so a warm restart does not re-apply the whole log — cold start no longer grows
	// with the lifetime event count. A fresh database has an empty checkpoint, so the
	// first boot still applies everything; an explicit Rebuild re-derives from zero.
	proj := projections.New(d.Store)
	if err := proj.ProjectCatchUp(ctx, d.Log); err != nil {
		return nil, fmt.Errorf("server: project event log: %w", err)
	}

	// 2) Orchestrator + outbox + API.
	s.outbox = orchestrator.NewOutbox(d.Store)
	orch := orchestrator.NewOrchestrator(d.Log, d.Store, s.outbox)
	idem := orchestrator.NewIdempotency(d.Store)
	// Retain orch/idem + the served profile so the issuance protocols (EXC-WIRE-02)
	// mint through the SAME event-sourced (AN-2), idempotent (AN-5), profile-gated
	// path the API mint uses.
	s.orch = orch
	s.idem = idem
	s.defaultProfile = d.DefaultProfile

	// Heal the append-then-project crash window (SPINE-011): Transition appends a
	// lifecycle event (durable, AN-2) and then, in a separate transaction, projects
	// it and enqueues its outbox side effect (AN-6). A crash in that gap leaves the
	// event but not the effect. On boot we reconcile: re-derive any missing side
	// effect from the log and enqueue it idempotently (keyed by event ID), so a
	// recorded transition that was never acted on is recovered before the dispatcher
	// starts. Effects that already landed are left untouched. This is cheap and safe
	// to run every boot.
	if healed, err := orch.ReconcileOutbox(ctx, d.Log); err != nil {
		return nil, fmt.Errorf("server: reconcile outbox side effects: %w", err)
	} else if healed > 0 && d.Logger != nil {
		d.Logger.Warn("reconciled outbox side effects missed by an append-then-project crash",
			slog.Int("healed", healed))
	}
	// Bound idempotency_keys with a background retention sweep (SPINE-002): the
	// served mutation path records one row per Idempotency-Key, and the GC worker
	// reclaims completed keys past the retention window so the table cannot grow
	// without limit. AN-5 still holds within the window.
	s.idemGC = idemgc.New(d.Store, d.IdempotencyRetention)
	// Bound the outbox the same way (SPINE-003): every external effect writes one
	// outbox row, and on delivery it is marked delivered but never removed. The purge
	// worker reclaims delivered rows past the retention window so the table — and its
	// backups — stay bounded; pending/failed rows are never touched, so at-least-once
	// delivery (AN-6) is unaffected.
	s.outboxGC = outboxgc.New(d.Store, d.OutboxRetention)

	// Agent enrollment (F3/F15, S5.1): mint one-time bootstrap tokens and sign
	// agents' CSRs into mTLS client certificates. Tokens are tenant-bound at mint
	// and redeemed single-use through the durable, tenant-scoped store (WIRE-003),
	// so they survive restarts, redeem on any instance, and yield a
	// tenant-attributed certificate. Defaults are prepended so a caller's APIOptions
	// still override them.
	authority, err := enroll.NewAuthority("trustctl Agent Enrollment CA", storeTokenStore{st: d.Store})
	if err != nil {
		return nil, fmt.Errorf("server: create enrollment authority: %w", err)
	}
	ea := enrollAuthority{authority}
	defaults := []api.Option{api.WithAgentEnrollment(ea), api.WithAgentEnroller(ea)}
	// Wire the audit subsystem into the serving path (R2.1 / B5): the query and
	// export endpoints serve real data instead of HTTP 500. The signing key is
	// persistent (loaded from disk by Run), so signed evidence bundles verify
	// across restarts. A caller's APIOptions still override these defaults.
	var auditSvc *audit.Service
	if d.AuditSigningKey != nil {
		// The audit service anchors a tenant's queries on its latest sealed retention
		// boundary (R4.4), so the chain stays verifiable after archived records are
		// pruned. The same store is the retention worker's checkpoint sink below.
		auditSvc = audit.NewService(d.Log, d.AuditSigningKey, audit.WithCheckpoints(d.Store))
		defaults = append(defaults, api.WithAudit(auditSvc))
	}
	// Shed load per tenant on the guarded routes when a limiter is wired (R2.3).
	if d.RateLimiter != nil {
		defaults = append(defaults, api.WithRateLimiter(d.RateLimiter))
	}

	// EXC-WIRE-03 — wire the served policy / RA-separation / dual-control gate onto
	// the mutating issue/deploy/revoke path. Until now the OPA/Rego default-deny
	// engine (internal/policy), the RA scope split (certs:request ≠ certs:issue), and
	// dual-control approval (internal/approval) were library-only (SEC-002, SEC-005,
	// CORRECT-003) — the served mint was reachable without them, which is RED-004 "the
	// loaded gun". Here we build them and hand them to the API so the running binary
	// enforces them. The bulkhead set is resolved now (it is also reused for the HTTP
	// pools below) so the policy engine can run on its own isolated pool (AN-7).
	s.bulk = d.Bulkhead
	if s.bulk == nil {
		s.bulk = bulkhead.Default()
	}
	gate, approvals, err := buildMutationGate(d, s.bulk)
	if err != nil {
		return nil, err
	}
	defaults = append(defaults, api.WithMutationGate(gate))
	if approvals != nil {
		defaults = append(defaults, api.WithApprovals(approvals))
	}

	// EXC-WIRE-01 — wire the served OIDC browser login + session + per-user → tenant
	// mapping onto the running binary. Until now api.WithAuth was library-only: the
	// /auth/* handlers existed in internal/api but no served composition ever called
	// WithAuth, so every /auth/* route 404'd and browser logins collapsed to one
	// DefaultTenant (SEC-001, WIRE-001, SURFACE-002, TENANT-004; RED-004). buildOIDCAuth
	// constructs the option from config: the IdP verifier (id_token signature/iss/aud/
	// nonce/exp/nbf/iat via the AN-3 JOSE boundary), a persistent session HMAC secret,
	// Secure-from-TLS cookies, and the per-user tenant mapper that scopes a session to
	// its real tenant under RLS (AN-1) — never to a blanket default. When OIDC is
	// disabled this is a no-op (token-only auth, as before); enabled-but-misconfigured
	// fails closed here. RED-004 stays shut: a session carries only the roles its
	// mapping grants, and the requester scope still excludes certs:issue, so a freshly
	// logged-in user cannot self-issue — issuance remains behind the EXC-WIRE-03 gate.
	authOpt, err := buildOIDCAuth(d.OIDC, d.SecurityHeaders.TLS, d.AuthHTTPClient)
	if err != nil {
		return nil, err
	}
	if authOpt != nil {
		defaults = append(defaults, authOpt)
	}

	apiOpts := append(defaults, d.APIOptions...)
	a := api.New(d.Store, idem, orch, apiOpts...)

	// 3) Provision the issuing CA inside the signer (AN-4). If no signer is
	// available, leave the CA unset — issuance then fails closed.
	if d.Signer != nil {
		if c := d.Signer.Client(); c != nil {
			if err := s.provisionCA(ctx, c, d.CACommonName, d.CACertFile); err != nil {
				return nil, fmt.Errorf("server: provision CA in signer: %w", err)
			}
		}
	}

	// 3a) Outbox handler. An explicit Deps.OutboxHandler wins (tests, custom
	// dispatchers). Otherwise, when an issuing CA is provisioned, the real
	// issuance dispatcher mints a certificate for a requested→issued transition
	// and records it in inventory; with no CA, issuance is unavailable so the
	// handler acknowledges (the entry cannot be served and must not dead-letter).
	switch {
	case s.obHandler != nil:
		// keep the injected handler
	case s.caSigner != nil:
		s.obHandler = &issuanceDispatcher{issue: s.IssueLeaf, orch: orch, idem: idem, store: d.Store, log: d.Log, defaultProfile: d.DefaultProfile}
	default:
		s.obHandler = orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error { return nil })
	}

	// 3b) Served revocation surface (EXC-REVOKE-01): when an issuing CA is
	// provisioned, stand up the OCSP responder + CRL endpoint + freshness scheduler.
	// They sign through the same signer-backed DigestSigner the leaf path uses, so
	// the CA key stays in the out-of-process signer (AN-4); they are tenant-scoped
	// under RLS (AN-1) and emit a ca.crl.published event on each CRL (AN-2). With no
	// CA the service is nil and the routes/scheduler are no-ops — revocation serving
	// is unavailable rather than backed by an in-process key.
	if s.caSigner != nil && len(s.caCertDER) > 0 {
		s.revoc = newRevocationService(d.Store, d.Log, IssuingCAID(), s.caSigner, s.caCertDER)
	}

	// 3c) Served issuance protocols (EXC-WIRE-02): when an issuing CA is provisioned,
	// build the enabled protocol servers (ACME, EST, SCEP, CMP, SSH, SPIFFE Workload
	// API). Each mints through the shared protocolIssuer — signer-backed (AN-3/AN-4),
	// tenant-scoped (AN-1), event-sourced (AN-2), idempotent (AN-5), profile-gated. The
	// HTTP protocols are mounted on the mux below; SPIFFE (a gRPC UDS service) is served
	// by RunSPIFFE. With no CA the protocols are nil and unserved — like revocation,
	// issuance is then unavailable rather than backed by an in-process key.
	if s.caSigner != nil && len(s.caCertDER) > 0 {
		protocols, perr := s.buildServedProtocols(ctx, d.Protocols, d.ProtocolTenant, d.ACMEValidators)
		if perr != nil {
			return nil, fmt.Errorf("server: build served protocols: %w", perr)
		}
		s.protocols = protocols
	}

	// 4) Observability (R2.2 / B6): a metrics registry, a tracer, and the readiness
	// aggregator that probes the real dependencies (DB, NATS, signer) — each under
	// a child span, so a /readyz call produces a trace spanning the subsystems.
	s.logger = d.Logger
	if s.logger == nil {
		s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s.registry = observ.NewRegistry()
	s.tracer = observ.NewTracer(d.TraceExporter)
	// Idempotency-key GC counter (SPINE-002): completed keys the background sweep
	// reclaims, so the table's bound is observable.
	s.mIdemPurged = s.registry.CounterVec("trustctl_idempotency_keys_purged_total", "Completed idempotency keys reclaimed by the retention sweep.", nil).WithLabelValues()
	// Outbox GC counter (SPINE-003): delivered outbox rows the background purge
	// reclaims, so the outbox table's bound is observable.
	s.mOutboxPurged = s.registry.CounterVec("trustctl_outbox_delivered_purged_total", "Delivered outbox rows reclaimed by the retention sweep.", nil).WithLabelValues()
	// Tailing projection worker + lag gauge (SPINE-009): a durable JetStream consumer
	// projects events appended out of band (not via the inline orchestrator path) and
	// exports projection lag — the number of events the read model is behind the log
	// head — so a stuck/divergent projection is observable instead of silently lagging
	// until the next boot replay. Applying an already-projected event is an idempotent
	// upsert, so the worker coexists with the orchestrator's inline projection.
	s.mProjLag = s.registry.Gauge("trustctl_projection_lag_events", "Number of events the read model is behind the head of the event log.")
	s.tailWorker = projections.NewTailWorker(d.Log, proj, s.mProjLag.Set, 0)
	// CRL freshness scheduler counter (EXC-REVOKE-01): CRLs regenerated by the
	// background freshness sweep, so the served CRL's freshness is observable.
	s.mCRLRegen = s.registry.CounterVec("trustctl_crl_regenerated_total", "CRLs regenerated by the served CRL freshness scheduler.", nil).WithLabelValues()

	// Audit retention worker (R4.4): when a retention window and an archive
	// directory are configured, a background worker archives audit records older
	// than the window to signed, offline-verifiable cold-storage bundles, seals a
	// checkpoint, then prunes them from the hot log — so Audit.Retention/ArchiveDir
	// do real work instead of being inert. Each run's counts are exported as
	// metrics; the run also emits an audit event of its own.
	if auditSvc != nil && d.AuditRetention > 0 && d.AuditArchiveDir != "" {
		s.retention = audit.NewRetentionWorker(auditSvc, d.Log, audit.DirArchiver{Dir: d.AuditArchiveDir}, d.Store, d.AuditRetention)
		s.mRetRuns = s.registry.CounterVec("trustctl_audit_retention_runs_total", "Audit retention runs that archived at least one segment.", nil).WithLabelValues()
		s.mRetArchived = s.registry.CounterVec("trustctl_audit_records_archived_total", "Audit records archived to cold storage by the retention worker.", nil).WithLabelValues()
		s.mRetPruned = s.registry.CounterVec("trustctl_audit_records_pruned_total", "Audit records pruned from the hot event log after archival.", nil).WithLabelValues()
	}

	checks := []observ.Check{
		{Name: "db", Probe: func(ctx context.Context) error { return d.Store.SystemPool().Ping(ctx) }},
		{Name: "nats", Probe: func(ctx context.Context) error { return d.Log.Ping(ctx) }},
	}
	if d.Signer != nil {
		checks = append(checks, observ.Check{Name: "signer", Probe: func(ctx context.Context) error {
			c := d.Signer.Client()
			if c == nil || !c.Healthy(ctx) {
				return errors.New("signer unreachable")
			}
			return nil
		}})
		// Publish signer up/restarts on the shared registry and take an initial
		// sample so /metrics reflects the signer immediately; RunSignerMonitor
		// keeps it current (SF.3).
		s.mSigner = observ.NewSignerMetrics(s.registry)
		s.sampleSigner(ctx)
	}
	s.readiness = observ.NewReadiness(s.tracer, checks...)

	// 5) Resilience (R2.3 / AN-7 in the live path): isolated, bounded worker pools
	// per subsystem. The API surface runs on the "api" pool so a flood there sheds
	// fast and can never starve liveness, readiness, metrics, or the signer — which
	// are served outside the API pool. s.bulk was resolved above (so the policy
	// engine could take its own pool, AN-7); reuse the same set here.
	apiHandler := bulkheadHandler(s.bulk, bulkhead.SubsystemAPI, a)
	// Heavy read families (the credential graph + risk scoring) run a per-request
	// O(inventory) build, so they get their OWN bounded pool (SPINE-005 / AN-7): a
	// burst of expensive graph/risk requests sheds on the query pool instead of
	// occupying the API workers and starving cheap CRUD (and /auth, /enroll). The
	// pool falls back to the api pool only if a custom Bulkhead set omits the query
	// pool (so a partial set never drops these routes).
	heavyHandler := apiHandler
	if s.bulk.Pool(bulkhead.SubsystemQuery) != nil {
		heavyHandler = bulkheadHandler(s.bulk, bulkhead.SubsystemQuery, a)
	}

	// 6) Root mux: liveness/readiness/metrics (never bulkheaded, so they answer even
	// under API saturation), the bulkheaded API (/api + /auth + /enroll), and the
	// web UI at /. The whole surface is wrapped with the observability middleware,
	// so every request is traced, counted, and access-logged (no secrets — AN-8).
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.readiness.Handler())
	mux.Handle("GET /metrics", s.registry.Handler())
	// The heavy read prefixes are registered as more-specific patterns than "/api/",
	// so Go's ServeMux routes them to the dedicated query pool while everything else
	// stays on the api pool (SPINE-005).
	mux.Handle("/api/v1/graph", heavyHandler)
	mux.Handle("/api/v1/graph/", heavyHandler)
	mux.Handle("/api/v1/risk/", heavyHandler)
	mux.Handle("/api/", apiHandler)
	mux.Handle("/auth/", apiHandler)
	mux.Handle("/enroll/", apiHandler)
	// Served revocation (EXC-REVOKE-01): the OCSP responder (/ocsp/{tenant}) and the
	// CRL endpoint (/crl/{tenant}) are PUBLIC by RFC design — relying parties query
	// certificate status without credentials — so they are mounted outside the
	// auth-guarded API but still on the API bulkhead pool, so an OCSP/CRL flood
	// sheds rather than starving the rest of the control plane (AN-7). They are
	// registered only when revocation is served (an issuing CA is provisioned).
	if s.revoc != nil {
		revMux := http.NewServeMux()
		s.revoc.routes(revMux)
		revHandler := bulkheadHandler(s.bulk, bulkhead.SubsystemAPI, revMux)
		mux.Handle("/ocsp/", revHandler)
		mux.Handle("/crl/", revHandler)
	}
	// Served issuance protocols (EXC-WIRE-02): mount the HTTP-served protocols
	// (ACME at /directory + /acme/, EST at /.well-known/est/, SCEP at /scep, CMP at
	// /cmp, the SSH CA at /ssh/). They are registered as more-specific patterns than
	// "/" so they take priority over the web UI catch-all. Each runs on the protocols
	// bulkhead pool inside its own handler (AN-7) and is tenant-scoped. They are
	// PUBLIC at the mux level (the protocols enforce their own auth: ACME JWS + DV,
	// EST Bearer-token + TLS, SCEP/CMP CMS, SSH via API token at the route) — they are
	// not behind the REST API's session/RBAC guard because RFC clients are not browser
	// principals. SPIFFE is served separately over its UDS (RunSPIFFE).
	if s.protocols != nil {
		s.protocols.routes(mux, s.bulk)
	}
	mux.Handle("/", webui.Handler(webui.Assets()))
	mw := observ.NewMiddleware(observ.Options{Logger: s.logger, Tracer: s.tracer, Registry: s.registry})
	// Web hardening (SEC-003/WIRE-005): the security-headers + CORS middleware is the
	// OUTERMOST wrapper, so CSP/HSTS/nosniff/frame-deny/Referrer-Policy and the
	// non-wildcard CORS decision are present on every served response — the API, the
	// auth/enroll routes, the web UI, and the always-on liveness/readiness/metrics
	// endpoints — including error and preflight responses.
	s.handler = securityHeadersMiddleware(d.SecurityHeaders, mw.Handler(mux))
	return s, nil
}

// issuingCAHandle is the stable signer handle for the issuing CA key. Using a
// fixed handle (rather than a random one) lets a restarted, persistent signer
// hand back the same key — so the CA is not silently rotated (R3.2).
const issuingCAHandle = "issuing-ca"

// provisionCA establishes the issuing CA whose key lives inside the signer (AN-4;
// the private key never enters the control plane's address space). It is stable
// across restarts (R3.2): if a persisted CA cert exists at caCertFile AND the
// signer still holds the CA key, both are reused. Otherwise it generates the key
// under the fixed handle, self-signs, and persists the cert for future boots.
func (s *Server) provisionCA(ctx context.Context, c *signing.Client, cn, caCertFile string) error {
	if cn == "" {
		cn = "trustctl Issuing CA"
	}

	// Reuse path: persisted cert + a signer that still has the CA key. Bind the
	// reloaded key to the CA-signing purpose so the signer's persisted
	// per-key constraint (SIGNER-002/003) is satisfied across a restart.
	if caCertFile != "" {
		if pemBytes, err := os.ReadFile(caCertFile); err == nil {
			if blk, _ := pem.Decode(pemBytes); blk != nil && blk.Type == "CERTIFICATE" {
				if remote, herr := c.SignerForHandleWithPurpose(ctx, issuingCAHandle, signing.PurposeCASign); herr == nil {
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
	remote, err := c.GenerateConstrainedKeyHandle(ctx, crypto.ECDSAP256, issuingCAHandle,
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

// Handler returns the assembled HTTP handler (for httptest and for Run).
func (s *Server) Handler() http.Handler { return s.handler }

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
		der, err := crypto.SignLeafFromCSRWithProfile(s.caCertDER, s.caSigner, csrDER, ttl, s.leafProfile)
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

// RevocationServed reports whether the served revocation surface (OCSP + CRL +
// scheduler) is active — i.e. an issuing CA is provisioned so OCSP/CRL sign
// through the signer. It is the EXC-REVOKE-01 wiring assertion.
func (s *Server) RevocationServed() bool { return s.revoc != nil }

// ServedProtocols reports the issuance protocols the running binary serves
// (EXC-WIRE-02): the subset of {acme,est,scep,cmp,ssh,spiffe} actually mounted, in a
// stable order. Empty when no issuing CA is provisioned or all protocols are
// disabled. It is the EXC-WIRE-02 wiring assertion (and is logged at startup).
func (s *Server) ServedProtocols() []string {
	if s.protocols == nil {
		return nil
	}
	return append([]string(nil), s.protocols.names...)
}

// acmeHandlerForTest returns the served ACME http.Handler, or nil when ACME is not
// served. Exported (test-only via the unexported name) so the acceptance test can
// drive the SAME served ACME handler the binary mounts, without re-implementing the
// composition. It is the wire-in proof seam for ACME.
func (s *Server) acmeHandlerForTest() http.Handler {
	if s.protocols == nil || s.protocols.acme == nil {
		return nil
	}
	return s.protocols.acme
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
			s.logger.Warn("crl scheduler sweep failed", slog.String("error", err.Error()))
			return
		}
		if n > 0 {
			if s.mCRLRegen != nil {
				s.mCRLRegen.Add(float64(n))
			}
			s.logger.Info("crl scheduler regenerated CRLs", slog.Int("regenerated", n))
		}
	})
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
		s.logger.Error("audit retention run failed", slog.String("error", err.Error()))
		return sum, err
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

// Drain delivers any pending outbox entries through the configured handler — the
// shutdown step that guarantees no enqueued external effect is lost (AN-6).
func (s *Server) Drain(ctx context.Context) error {
	_, err := s.outbox.Dispatch(ctx, s.obHandler)
	return err
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
