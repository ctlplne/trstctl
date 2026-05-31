package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"certctl.io/certctl/internal/audit"
	"certctl.io/certctl/internal/config"
	"certctl.io/certctl/internal/events"
	"certctl.io/certctl/internal/signing"
	"certctl.io/certctl/internal/store"
)

// Run opens the datastore and event log, supervises the signer as a child
// process (AN-4), assembles the control plane, and serves until ctx is
// cancelled — then shuts down in order (stop accepting → drain the outbox →
// close the event log and datastore). It is the production composition the
// certctl binary calls.
func Run(ctx context.Context, cfg *config.Config) error {
	if cfg.Postgres.Mode != config.PostgresExternal || cfg.Postgres.DSN == "" {
		return errors.New("server: a serving control plane requires an external Postgres DSN (set CERTCTL_POSTGRES_MODE=external and CERTCTL_POSTGRES_DSN)")
	}
	st, err := store.Open(ctx, cfg.Postgres.DSN)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	if err := st.Migrate(ctx); err != nil {
		st.Close()
		return fmt.Errorf("migrate: %w", err)
	}
	log, err := events.Open(ctx, cfg.NATS)
	if err != nil {
		st.Close()
		return fmt.Errorf("open event log: %w", err)
	}

	signerBin, err := siblingBinary("certctl-signer")
	if err != nil {
		_ = log.Close()
		st.Close()
		return err
	}
	socket := filepath.Join(os.TempDir(), "certctl-signer.sock")
	sup, err := signing.Supervise(ctx, signerBin, socket)
	if err != nil {
		_ = log.Close()
		st.Close()
		return fmt.Errorf("start signer: %w", err)
	}
	defer sup.Close()

	// Load (or create) the persistent audit export key so the audit subsystem is
	// wired into the serving path and signed evidence bundles verify across
	// restarts (R2.1 / B5).
	auditKey, err := audit.LoadOrCreateSigningKey(cfg.Audit.SigningKeyFile, "audit-export")
	if err != nil {
		_ = log.Close()
		st.Close()
		return fmt.Errorf("audit signing key: %w", err)
	}

	srv, err := Build(ctx, Deps{Store: st, Log: log, Signer: sup, AuditSigningKey: auditKey})
	if err != nil {
		_ = log.Close()
		st.Close()
		return err
	}

	// Run the outbox dispatcher continuously (AN-6): external effects — issuance,
	// notifications — happen while the process is live, not only at shutdown
	// (closing the audit's "drains only at shutdown" finding). It stops before the
	// final drain so the two never race on the same entries.
	dispCtx, stopDispatcher := context.WithCancel(ctx)
	dispatcherDone := make(chan struct{})
	go func() { defer close(dispatcherDone); srv.RunDispatcher(dispCtx) }()

	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	ln, err := net.Listen("tcp", cfg.Server.Addr)
	if err != nil {
		stopDispatcher()
		<-dispatcherDone
		_ = srv.Shutdown(ctx)
		return fmt.Errorf("listen %s: %w", cfg.Server.Addr, err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- serveControlPlane(httpSrv, ln, cfg.Server.TLS, os.Stderr) }()

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			stopDispatcher()
			<-dispatcherDone
			_ = srv.Shutdown(context.Background())
			return fmt.Errorf("serve: %w", err)
		}
	}

	// Graceful shutdown: stop accepting connections, stop the dispatcher, then
	// drain + close in order. Stopping the dispatcher first means Shutdown's final
	// drain has exclusive ownership of the outbox.
	stopDispatcher()
	<-dispatcherDone
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
