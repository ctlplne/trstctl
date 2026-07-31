// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/config"
)

// TestDODGateProductionAssemblyCanary is the gate's always-run spine proof. It
// starts real embedded PostgreSQL and file-backed JetStream, constructs Deps with
// the same buildRunDeps function used by Run, passes those exact Deps to Build,
// then drives the resulting production handler. Per-capability runtime receipts
// add stronger route/emulator evidence as their manifest rows are promoted.
func TestDODGateProductionAssemblyCanary(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	auditKey, err := audit.LoadOrCreateSigningKey(cfg.Audit.SigningKeyFile, "audit-export")
	if err != nil {
		t.Fatalf("load audit signing key before event-log recovery: %v", err)
	}
	log, err := openHistoryAwareEventLog(
		ctx,
		config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")},
		st,
		auditKey,
	)
	if err != nil {
		t.Fatalf("open embedded event log: %v", err)
	}
	if err := log.HistoryRewriteReady(); err != nil {
		_ = log.Close()
		t.Fatalf("production event log lacks history recovery walls: %v", err)
	}

	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		_ = log.Close()
		t.Fatalf("build egress guard: %v", err)
	}
	deps, err := buildRunDeps(ctx, cfg, st, log, runSigner{}, runSecrets{}, slog.New(slog.NewTextHandler(io.Discard, nil)), guard, auditKey)
	if err != nil {
		_ = log.Close()
		t.Fatalf("production buildRunDeps: %v", err)
	}
	if deps.AuditSigningKey != auditKey {
		_ = log.Close()
		t.Fatal("production assembly reloaded a second audit key instead of reusing the recovery verifier key")
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		t.Fatalf("Build from production-assembled Deps: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("assembled GET /healthz = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
	}
}
