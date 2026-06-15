package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"trustctl.io/trustctl/internal/api"
	"trustctl.io/trustctl/internal/audit"
	"trustctl.io/trustctl/internal/config"
	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/events"
	"trustctl.io/trustctl/internal/logging"
	"trustctl.io/trustctl/internal/ratelimit"
	"trustctl.io/trustctl/internal/secrets"
	"trustctl.io/trustctl/internal/signing"
	"trustctl.io/trustctl/internal/store"
)

// Run opens the datastore and event log, supervises the signer as a child
// process (AN-4), assembles the control plane, and serves until ctx is
// cancelled — then shuts down in order (stop accepting → drain the outbox →
// close the event log and datastore). It is the production composition the
// trustctl binary calls.
func Run(ctx context.Context, cfg *config.Config) error {
	// Build the structured logger first (R2.2 / B6): it backs the request access log
	// and lifecycle events, and the bundled-datastore startup logs through it.
	logger, err := logging.New(logging.Options{Level: cfg.Log.Level, Format: cfg.Log.Format, Service: "trustctl"}, os.Stderr)
	if err != nil {
		return fmt.Errorf("build logger: %w", err)
	}

	// Resolve the datastore per config (R4.5): external connects to a managed
	// cluster by DSN; bundled starts the embedded single-node Postgres for
	// evaluation and is stopped on exit. The stop runs after the store closes
	// (deferred LIFO), so connections drain before the database stops.
	dsn, stopPG, err := openDatastore(cfg.Postgres, logger)
	if err != nil {
		return err
	}
	defer func() {
		if stopPG != nil {
			_ = stopPG()
		}
	}()

	st, err := store.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	// Migration gate (R2.5): inspect the plan first. When migrations are pending
	// and automatic migration is disabled, fail fast with guidance instead of
	// migrating silently — the pre-migration backup gate. Migrate itself takes an
	// advisory lock, so concurrent instances cannot double-apply.
	pending, err := st.PendingMigrations(ctx)
	if err != nil {
		st.Close()
		return fmt.Errorf("inspect migrations: %w", err)
	}
	if len(pending) > 0 {
		if !cfg.Migrate.Auto {
			st.Close()
			return fmt.Errorf("%d pending database migration(s) and automatic migration is disabled (TRUSTCTL_MIGRATE_AUTO=false): take a backup (trustctl --backup), then apply them with 'trustctl --migrate'; pending: %v", len(pending), pending)
		}
		logger.Info("applying pending database migrations", "count", len(pending))
	}
	if err := st.Migrate(ctx); err != nil {
		st.Close()
		return fmt.Errorf("migrate: %w", err)
	}

	// Provision and validate the credential KEK (R3.1): create it (0600) on first
	// boot and fail fast on a malformed key, so credentials-at-rest is ready before
	// serving. Held only transiently here.
	kek, err := secrets.LoadOrCreateKEK(cfg.Secrets.KEKFile)
	if err != nil {
		st.Close()
		return fmt.Errorf("provision credential KEK: %w", err)
	}
	kek.Destroy()

	log, err := events.Open(ctx, cfg.NATS)
	if err != nil {
		st.Close()
		return fmt.Errorf("open event log: %w", err)
	}

	// The signer is an isolated process (AN-4). In "child" mode the control plane
	// supervises it as a child (single binary), passing the sealed key store and
	// KEK so the issuing CA key persists and a restart preserves the CA (R3.2). In
	// "external" mode it connects to a separately deployed signer service (the
	// Compose/topology isolation).
	var signer SignerProvider
	var signerClose func()
	switch cfg.Signer.Mode {
	case config.SignerExternal:
		c, derr := signing.DialReady(ctx, cfg.Signer.Socket, 10*time.Second)
		if derr != nil {
			_ = log.Close()
			st.Close()
			return fmt.Errorf("connect external signer at %s: %w", cfg.Signer.Socket, derr)
		}
		signer = signing.StaticProvider{C: c}
		signerClose = func() { _ = c.Close() }
	default: // child
		signerBin, berr := siblingBinary("trustctl-signer")
		if berr != nil {
			_ = log.Close()
			st.Close()
			return berr
		}
		socket := cfg.Signer.Socket
		if socket == "" {
			socket = filepath.Join(os.TempDir(), "trustctl-signer.sock")
		}
		sup, serr := signing.Supervise(ctx, signerBin, socket, "--keystore", cfg.Signer.KeyStoreDir, "--kek", cfg.Secrets.KEKFile)
		if serr != nil {
			_ = log.Close()
			st.Close()
			return fmt.Errorf("start signer: %w", serr)
		}
		signer = sup
		signerClose = sup.Close
	}
	defer signerClose()

	// Load (or create) the persistent audit export key so the audit subsystem is
	// wired into the serving path and signed evidence bundles verify across
	// restarts (R2.1 / B5).
	auditKey, err := audit.LoadOrCreateSigningKey(cfg.Audit.SigningKeyFile, "audit-export")
	if err != nil {
		_ = log.Close()
		st.Close()
		return fmt.Errorf("audit signing key: %w", err)
	}

	// Build the per-tenant rate limiter from config (R2.3). Disabled config leaves
	// it nil (no limiting); the bulkheads default inside Build (always on, AN-7).
	var rateLimiter api.RateLimiter
	if cfg.RateLimit.Enabled {
		window, werr := cfg.RateLimit.WindowDuration()
		if werr != nil {
			_ = log.Close()
			st.Close()
			return fmt.Errorf("rate limit window: %w", werr)
		}
		rateLimiter = ratelimit.FromRate(st, cfg.RateLimit.Requests, window)
	}

	// Parse the audit retention window (R4.4). Empty means indefinite (the worker
	// stays off); a positive window plus an archive directory enables it.
	retention, err := cfg.Audit.RetentionDuration()
	if err != nil {
		_ = log.Close()
		st.Close()
		return fmt.Errorf("audit retention: %w", err)
	}

	// The served-leaf issuance profile (PKIGOV-001): CDP/AIA/policy pointers from
	// config are stamped on every leaf the served path mints (the SKI is always
	// set inside the crypto boundary). DefaultProfile, when set, binds the served
	// mint to a tenant profile and rejects out-of-profile requests (PKIGOV-002).
	leafProfile := crypto.LeafProfile{
		CRLDistributionPoints: cfg.CA.CRLDistributionPoints,
		OCSPServers:           cfg.CA.OCSPServers,
		IssuingCertificateURL: cfg.CA.IssuerURLs,
		CertificatePolicyOIDs: cfg.CA.CertificatePolicyOIDs,
	}

	srv, err := Build(ctx, Deps{Store: st, Log: log, Signer: signer, CACertFile: cfg.CA.CertFile,
		LeafProfile: leafProfile, DefaultProfile: cfg.CA.DefaultProfile,
		// EXC-WIRE-03: wire the served policy / RA-separation / dual-control gate onto
		// the mutating issue/deploy/revoke path from config (closes SEC-002/SEC-005/
		// CORRECT-003; the served half of RED-004). Off by default so an upgrade does
		// not silently start denying; the RA scope split is always enforced.
		PolicyModule:      cfg.CA.Policy.Module,
		EnablePolicyGate:  cfg.CA.Policy.Enabled,
		RequireApproval:   cfg.CA.Policy.RequireApproval,
		RequiredApprovals: cfg.CA.Policy.RequiredApprovals,
		AuditSigningKey:   auditKey, AuditRetention: retention, AuditArchiveDir: cfg.Audit.ArchiveDir,
		Logger: logger, RateLimiter: rateLimiter,
		// Web hardening (SEC-003/WIRE-005): emit HSTS only when the control plane is
		// served over TLS (internal or file mode), and apply the operator's CORS
		// allow-list (empty = same-origin only).
		SecurityHeaders: SecurityHeaders{
			TLS:            cfg.Server.TLS.Mode != config.TLSDisabled,
			AllowedOrigins: cfg.Server.CORSAllowedOrigins,
		},
		// Served issuance protocols (EXC-WIRE-02): mount the enabled RFC protocol
		// servers (ACME/EST/SCEP/CMP/SPIFFE/SSH) on the running binary, each minting
		// through the signer-backed, tenant-scoped, event-sourced, idempotent issuance
		// path. A protocol with no configured tenant fails closed at issuance (it must
		// not mint into a blank tenant — AN-1). They are served only when an issuing CA
		// is provisioned.
		Protocols: cfg.Protocols,
		// Served OIDC browser login + session + per-user → tenant mapping (EXC-WIRE-01):
		// when auth.oidc.enabled, the running binary serves /auth/login, /auth/callback,
		// /auth/me, /auth/logout and a session cookie authorizes API calls under the same
		// RBAC + RLS tenant scoping as an API token (closes SEC-001/WIRE-001/SURFACE-002/
		// TENANT-004). Cookies are Secure whenever the control plane serves TLS. Disabled
		// (the default) keeps token-only auth; enabled-but-misconfigured fails closed in
		// Build.
		OIDC: cfg.Auth.OIDC})
	if err != nil {
		_ = log.Close()
		st.Close()
		return err
	}
	logger.Info("control plane assembled",
		slog.String("addr", cfg.Server.Addr), slog.String("tls_mode", cfg.Server.TLS.Mode))

	// Run the outbox dispatcher continuously (AN-6): external effects — issuance,
	// notifications — happen while the process is live, not only at shutdown
	// (closing the audit's "drains only at shutdown" finding). It stops before the
	// final drain so the two never race on the same entries.
	dispCtx, stopDispatcher := context.WithCancel(ctx)
	dispatcherDone := make(chan struct{})
	go func() { defer close(dispatcherDone); srv.RunDispatcher(dispCtx) }()

	// Run the audit retention worker on its own cadence (R4.4): it archives records
	// past the window to signed cold-storage bundles and prunes them from the hot
	// log, so Audit.Retention/ArchiveDir do real work rather than nothing. A no-op
	// when not configured. Stopped alongside the dispatcher before shutdown.
	retCtx, stopRetention := context.WithCancel(ctx)
	retentionDone := make(chan struct{})
	go func() { defer close(retentionDone); srv.RunRetention(retCtx) }()

	// Sample the out-of-process signer's health/restarts into the metrics registry
	// on a fixed cadence (SF.3). A no-op when no signer is configured; stopped with
	// the other background workers before shutdown.
	sigCtx, stopSigner := context.WithCancel(ctx)
	signerDone := make(chan struct{})
	go func() { defer close(signerDone); srv.RunSignerMonitor(sigCtx) }()

	// Reclaim expired idempotency keys on a fixed cadence (SPINE-002): the served
	// mutation path records one row per Idempotency-Key, so without reclamation the
	// idempotency_keys table — and its backups — would grow without bound. The sweep
	// deletes completed keys past the retention window (AN-5 still holds inside it).
	// Stopped with the other background workers before shutdown.
	idemCtx, stopIdemGC := context.WithCancel(ctx)
	idemGCDone := make(chan struct{})
	go func() { defer close(idemGCDone); srv.RunIdempotencyGC(idemCtx) }()

	// Reclaim delivered outbox rows on a fixed cadence (SPINE-003): every external
	// effect writes one outbox row that is marked delivered but never removed, so
	// without reclamation the outbox table — and its backups — would grow without
	// bound. The purge deletes delivered rows past the retention window; pending/
	// failed rows are untouched, so at-least-once delivery (AN-6) is preserved.
	// Stopped before the final drain so it never races the dispatcher on a row.
	outboxGCCtx, stopOutboxGC := context.WithCancel(ctx)
	outboxGCDone := make(chan struct{})
	go func() { defer close(outboxGCDone); srv.RunOutboxGC(outboxGCCtx) }()

	// Tail the event stream with a durable consumer (SPINE-009): events appended out
	// of band (not via the inline orchestrator projection) are applied promptly, and
	// the projection-lag gauge tracks how far the read model is behind the log head so
	// a stuck/divergent projection is observable. Stopped before the final drain.
	tailCtx, stopTail := context.WithCancel(ctx)
	tailDone := make(chan struct{})
	go func() { defer close(tailDone); srv.RunProjectionTail(tailCtx) }()

	// Regenerate served CRLs on a freshness cadence (EXC-REVOKE-01): each tenant's
	// CRL is regenerated ahead of its nextUpdate (and a first one is generated on
	// demand) so the CRL the CDP serves is never stale. CRLs are signed through the
	// out-of-process signer (AN-4); a no-op when no issuing CA is provisioned.
	// Stopped before the final drain with the other background workers.
	crlCtx, stopCRL := context.WithCancel(ctx)
	crlDone := make(chan struct{})
	go func() { defer close(crlDone); srv.RunCRLScheduler(crlCtx) }()

	// Serve the SPIFFE Workload API over its UDS (EXC-WIRE-02 / INTEROP-004): a stock
	// go-spiffe / spiffe-helper / Envoy SDS client dials the socket to FetchX509SVID,
	// signed through the out-of-process signer (AN-4). A no-op unless protocols.spiffe
	// is enabled and an issuing CA is provisioned. Stopped with the other workers.
	spiffeCtx, stopSPIFFE := context.WithCancel(ctx)
	spiffeDone := make(chan struct{})
	go func() { defer close(spiffeDone); srv.RunSPIFFE(spiffeCtx) }()
	if served := srv.ServedProtocols(); len(served) > 0 {
		logger.Info("served issuance protocols mounted", slog.Any("protocols", served))
	}

	// stopBackground halts the background workers and waits for them to exit, so the
	// final drain in Shutdown owns the outbox exclusively and no worker is mid-run
	// when the event log closes.
	stopBackground := func() {
		stopDispatcher()
		<-dispatcherDone
		stopRetention()
		<-retentionDone
		stopSigner()
		<-signerDone
		stopIdemGC()
		<-idemGCDone
		stopOutboxGC()
		<-outboxGCDone
		stopTail()
		<-tailDone
		stopCRL()
		<-crlDone
		stopSPIFFE()
		<-spiffeDone
	}

	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	ln, err := net.Listen("tcp", cfg.Server.Addr)
	if err != nil {
		stopBackground()
		_ = srv.Shutdown(ctx)
		return fmt.Errorf("listen %s: %w", cfg.Server.Addr, err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- serveControlPlane(httpSrv, ln, cfg.Server.TLS, os.Stderr) }()

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			stopBackground()
			_ = srv.Shutdown(context.Background())
			return fmt.Errorf("serve: %w", err)
		}
	}

	// Graceful shutdown: stop accepting connections, stop the dispatcher, then
	// drain + close in order. Stopping the dispatcher first means Shutdown's final
	// drain has exclusive ownership of the outbox.
	logger.Info("control plane shutting down")
	stopBackground()
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	return srv.Shutdown(shutCtx)
}

func siblingBinary(name string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate executable: %w", err)
	}
	return filepath.Join(filepath.Dir(exe), name), nil
}

// openDatastore resolves the PostgreSQL datastore per config (R4.5). External mode
// connects to a deployed cluster by DSN. Bundled mode starts the embedded
// single-node Postgres for evaluation and returns a stop function (nil for
// external). An invalid mode fails fast — there is no default that silently cannot
// serve.
func openDatastore(pg config.Postgres, logger *slog.Logger) (dsn string, stop func() error, err error) {
	switch pg.Mode {
	case config.PostgresExternal:
		if pg.DSN == "" {
			return "", nil, errors.New("server: external Postgres requires a DSN (set TRUSTCTL_POSTGRES_DSN), or use TRUSTCTL_POSTGRES_MODE=bundled for single-node evaluation")
		}
		return pg.DSN, nil, nil
	case config.PostgresBundled:
		logger.Info("starting bundled single-node PostgreSQL for evaluation",
			slog.String("data_dir", pg.DataDir),
			slog.String("note", "production should run TRUSTCTL_POSTGRES_MODE=external against a managed cluster"))
		dsn, stop, err := startBundledPostgres(pg)
		if err != nil {
			return "", nil, err
		}
		logger.Info("bundled PostgreSQL ready", slog.Int("port", bundledPort(pg)))
		return dsn, stop, nil
	default:
		return "", nil, fmt.Errorf("server: invalid postgres.mode %q (want %q or %q)", pg.Mode, config.PostgresExternal, config.PostgresBundled)
	}
}
