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

	srv, err := Build(ctx, Deps{Store: st, Log: log, Signer: signer, CACertFile: cfg.CA.CertFile,
		AuditSigningKey: auditKey, AuditRetention: retention, AuditArchiveDir: cfg.Audit.ArchiveDir,
		Logger: logger, RateLimiter: rateLimiter})
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
