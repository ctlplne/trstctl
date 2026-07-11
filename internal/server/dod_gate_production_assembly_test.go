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

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// TestDODGateProductionAssemblyCanary is the gate's always-run spine proof. It
// starts real embedded PostgreSQL and file-backed JetStream, constructs Deps with
// the same buildRunDeps function used by Run, passes those exact Deps to Build,
// then drives the resulting production handler. Per-capability runtime receipts
// add stronger route/emulator evidence as their manifest rows are promoted.
func TestDODGateProductionAssemblyCanary(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatalf("open embedded event log: %v", err)
	}

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		_ = log.Close()
		t.Fatalf("build egress guard: %v", err)
	}
	deps, err := buildRunDeps(ctx, cfg, st, log, runSigner{}, runSecrets{}, slog.New(slog.NewTextHandler(io.Discard, nil)), guard)
	if err != nil {
		_ = log.Close()
		t.Fatalf("production buildRunDeps: %v", err)
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
