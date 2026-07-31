// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// TestServedTenantKeyDomainSealWaitsForCachedResultAndReplaysAfterSeal drives
// the exact default-binary composition. The API only queues the event/outbox
// request; the bounded dispatcher proves the completed result wall, commits the
// seal, and an identical retry still receives the byte-identical 202 receipt
// even though ordinary tenant-result decryption now fails closed.
func TestServedTenantKeyDomainSealWaitsForCachedResultAndReplaysAfterSeal(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{
		TenantID: servedTestTenant, Name: "tenant-seal-served", EventSeq: 1,
	}); err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, st, servedTestTenant, "keys:read", "keys:write")

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "deployment-kek")
	wrapperPath := filepath.Join(t.TempDir(), "tenant-wrapper.key")
	if err := os.WriteFile(wrapperPath, bytes.Repeat([]byte{0x7a}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Secrets.TenantSealLocalWrappers = []config.TenantSealLocalWrapper{{
		ID: "tenant-served-wrapper", File: wrapperPath,
	}}
	auditKey, err := audit.LoadOrCreateSigningKey(cfg.Audit.SigningKeyFile, "audit-export")
	if err != nil {
		t.Fatal(err)
	}
	log, err := openHistoryAwareEventLog(
		ctx,
		config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")},
		st,
		auditKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	secrets, err := loadRunSecrets(cfg)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	t.Cleanup(secrets.Close)
	deps, err := buildRunDeps(
		ctx, cfg, st, log, runSigner{}, secrets,
		slog.New(slog.NewTextHandler(io.Discard, nil)), guard, auditKey,
	)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	migrate := servedTenantSealRequest(
		t, srv, token, http.MethodPost,
		"/api/v1/platform/tenant-key-domain/migrate", "tenant-migrate-served",
		[]byte(`{"wrapper_kind":"local_file","wrapper_id":"tenant-served-wrapper"}`),
	)
	if migrate.Code != http.StatusOK {
		t.Fatalf("migrate = %d body=%s", migrate.Code, migrate.Body.String())
	}

	first := servedTenantSealRequest(
		t, srv, token, http.MethodPost,
		"/api/v1/platform/tenant-key-domain/seal", "tenant-seal-served", nil,
	)
	if first.Code != http.StatusAccepted {
		t.Fatalf("queue seal = %d body=%s", first.Code, first.Body.String())
	}
	var receipt api.TenantKeyDomainSealReceipt
	if err := json.Unmarshal(first.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if !receipt.Accepted || receipt.OperationID == "" || receipt.State != store.TenantKeyDomainStateSealQueued {
		t.Fatalf("seal receipt = %+v", receipt)
	}
	queued, err := deps.TenantKeyDomains.Status(ctx, servedTestTenant)
	if err != nil || queued.State != store.TenantKeyDomainStateSealQueued {
		t.Fatalf("queued domain = %+v err=%v", queued, err)
	}

	n, err := srv.outbox.DispatchScoped(
		ctx,
		srv.obHandler,
		orchestrator.DestinationScope{IncludePrefixes: []string{store.TenantKeyDomainSealDestination}},
	)
	if err != nil || n != 1 {
		t.Fatalf("dispatch tenant seal = %d/%v, want 1/nil", n, err)
	}
	sealed, err := deps.TenantKeyDomains.Status(ctx, servedTestTenant)
	if err != nil || sealed.State != store.TenantKeyDomainStateSealed ||
		sealed.OperationID == nil || *sealed.OperationID != receipt.OperationID {
		t.Fatalf("sealed domain = %+v err=%v", sealed, err)
	}

	replay := servedTenantSealRequest(
		t, srv, token, http.MethodPost,
		"/api/v1/platform/tenant-key-domain/seal", "tenant-seal-served", nil,
	)
	if replay.Code != http.StatusAccepted || !bytes.Equal(replay.Body.Bytes(), first.Body.Bytes()) {
		t.Fatalf("sealed replay = %d body=%s, want byte-identical %s", replay.Code, replay.Body.String(), first.Body.String())
	}

	unseal := servedTenantSealRequest(
		t, srv, token, http.MethodPost,
		"/api/v1/platform/tenant-key-domain/unseal", "tenant-unseal-served", nil,
	)
	if unseal.Code != http.StatusOK {
		t.Fatalf("unseal = %d body=%s", unseal.Code, unseal.Body.String())
	}
}

func servedTenantSealRequest(
	t *testing.T,
	srv *Server,
	token, method, path, idempotencyKey string,
	body []byte,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}
