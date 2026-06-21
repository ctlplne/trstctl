package server

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

var serverTestPG struct {
	once sync.Once
	dsn  string
	stop func() error
	dir  string
	err  error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if serverTestPG.stop != nil {
		_ = serverTestPG.stop()
	}
	if serverTestPG.dir != "" {
		_ = os.RemoveAll(serverTestPG.dir)
	}
	os.Exit(code)
}

func serverTestPostgresDSN(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	serverTestPG.once.Do(func() {
		dir, err := os.MkdirTemp("", "trstctl-server-pg")
		if err != nil {
			serverTestPG.err = err
			return
		}
		serverTestPG.dir = dir
		started := time.Now()
		dsn, stop, err := startBundledPostgres(config.Postgres{
			Mode:    config.PostgresBundled,
			DataDir: dir,
			Port:    freeTCPPort(t),
		})
		if err != nil {
			_ = os.RemoveAll(dir)
			serverTestPG.dir = ""
			serverTestPG.err = fmt.Errorf("shared embedded postgres start after %s: %w", time.Since(started).Round(time.Millisecond), err)
			return
		}
		serverTestPG.dsn = dsn
		serverTestPG.stop = stop
	})
	if serverTestPG.err != nil {
		t.Fatalf("server test postgres: %v", serverTestPG.err)
	}
	return serverTestPG.dsn
}

func newServerTestStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, serverTestPostgresDSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	resetServerTestStore(t, st)
	return st
}

func resetServerTestStore(t *testing.T, st *store.Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := st.SystemPool().Exec(ctx,
		`TRUNCATE tenants, idempotency_keys, outbox, rate_limits,
		          owners, issuers, identities, identity_transitions, deployment_targets,
		          agents, agent_bootstrap_tokens, policy_bindings, tenant_members, attestations, api_tokens, certificates,
		          ca_authorities, ca_key_ceremonies, ca_ceremony_approvals,
		          ca_issued_certs, ca_crls, ssh_keys, ct_watched_domains, ct_log_checkpoints,
		          crypto_assets, credentials, audit_checkpoints, certificate_profiles,
		          discovery_sources, discovery_schedules, discovery_runs, discovery_findings,
		          connector_delivery_receipts, lifecycle_rotation_runs,
		          secret_store, read_model_snapshots,
		          issuance_approval_requests, issuance_approvals
		 RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("reset shared server postgres: %v", err)
	}
	if _, err := st.SystemPool().Exec(ctx, `UPDATE projection_checkpoint SET applied_seq = 0 WHERE id = 1`); err != nil {
		t.Fatalf("reset projection checkpoint: %v", err)
	}
	if _, err := st.SystemPool().Exec(ctx, `UPDATE outbox_reconciliation_checkpoint SET reconciled_seq = 0, updated_at = now() WHERE id = 1`); err != nil {
		t.Fatalf("reset outbox reconciliation checkpoint: %v", err)
	}
}
