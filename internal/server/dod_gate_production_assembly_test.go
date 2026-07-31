// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// TestDODGateProductionAssemblyCanary is the gate's always-run spine proof. It
// starts real embedded PostgreSQL and file-backed JetStream, constructs Deps with
// the same buildRunDeps function used by Run, passes those exact Deps to Build,
// then drives the resulting production handler. Per-capability runtime receipts
// add stronger route/emulator evidence as their manifest rows are promoted.
func TestDODGateProductionAssemblyCanary(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: servedTestTenant, Name: "DoD tenant", EventSeq: 1}); err != nil {
		t.Fatalf("seed DoD tenant: %v", err)
	}
	token := seedScopedToken(t, st, servedTestTenant, "access:read", "keys:read")
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "secrets-kek")
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
	secrets, err := loadRunSecrets(cfg)
	if err != nil {
		_ = log.Close()
		t.Fatalf("load production run secrets: %v", err)
	}
	t.Cleanup(secrets.Close)
	deps, err := buildRunDeps(ctx, cfg, st, log, runSigner{}, secrets, slog.New(slog.NewTextHandler(io.Discard, nil)), guard, auditKey)
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

	request = httptest.NewRequest(http.MethodGet, "/api/v1/platform/system", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder = httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("assembled GET /api/v1/platform/system = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
	}
	var readout api.SystemReadout
	if err := json.NewDecoder(recorder.Body).Decode(&readout); err != nil {
		t.Fatalf("decode platform system readout: %v", err)
	}
	if readout.IdempotencyResults.State != "empty" || readout.IdempotencyResults.RawV0Remaining != 0 {
		t.Fatalf("default-binary idempotency protection readout = %+v", readout.IdempotencyResults)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/platform/tenant-key-domain", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder = httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("assembled GET /api/v1/platform/tenant-key-domain = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
	}
	var tenantDomain api.TenantKeyDomainStatus
	if err := json.NewDecoder(recorder.Body).Decode(&tenantDomain); err != nil {
		t.Fatalf("decode tenant key-domain status: %v", err)
	}
	if !tenantDomain.Served || tenantDomain.State != "legacy" ||
		tenantDomain.ProtectionMode != "legacy_deployment_kek" ||
		!tenantDomain.LocalWrapperZeroEgress {
		t.Fatalf("default-binary tenant key-domain status = %+v", tenantDomain)
	}
}
