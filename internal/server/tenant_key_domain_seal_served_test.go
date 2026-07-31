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
	"strings"
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

// TestServedTenantKeyDomainSealFailsSecretReadsClosedAndKeepsNeighborAvailable
// proves the customer-facing reason for the tenant cipher seam. Migration must
// not make an unsealed tenant's already-stored secret unreadable, sealing tenant
// A must return one honest locked status, and tenant B must continue using its
// independent RLS/cipher path throughout the transition.
func TestServedTenantKeyDomainSealFailsSecretReadsClosedAndKeepsNeighborAvailable(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	const sealedTenant = "33333333-3333-3333-3333-333333333333"
	const neighborTenant = "44444444-4444-4444-4444-444444444444"
	for _, tenant := range []store.Tenant{
		{TenantID: sealedTenant, Name: "tenant-seal-served", EventSeq: 1},
		{TenantID: neighborTenant, Name: "tenant-seal-neighbor", EventSeq: 1},
	} {
		if err := st.UpsertTenant(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	tokenA := seedScopedToken(t, st, sealedTenant, "keys:read", "keys:write", "secrets:read", "secrets:write")
	tokenB := seedScopedToken(t, st, neighborTenant, "secrets:read", "secrets:write")

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Secrets.EnableAPI = true
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "deployment-kek")
	wrapperPath := filepath.Join(t.TempDir(), "tenant-wrapper.key")
	if err := os.WriteFile(wrapperPath, bytes.Repeat([]byte{0x6c}, 32), 0o600); err != nil {
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

	createA := servedTenantSealRequest(t, srv, tokenA, http.MethodPost, "/api/v1/secrets/store", "tenant-a-secret-create", []byte(`{"name":"db/password","value":"tenant-a-secret"}`))
	if createA.Code != http.StatusCreated {
		t.Fatalf("create tenant A secret = %d body=%s", createA.Code, createA.Body.String())
	}
	createB := servedTenantSealRequest(t, srv, tokenB, http.MethodPost, "/api/v1/secrets/store", "tenant-b-secret-create", []byte(`{"name":"db/password","value":"tenant-b-secret"}`))
	if createB.Code != http.StatusCreated {
		t.Fatalf("create tenant B secret = %d body=%s", createB.Code, createB.Body.String())
	}

	migrate := servedTenantSealRequest(
		t, srv, tokenA, http.MethodPost,
		"/api/v1/platform/tenant-key-domain/migrate", "tenant-migrate-secret-path",
		[]byte(`{"wrapper_kind":"local_file","wrapper_id":"tenant-served-wrapper"}`),
	)
	if migrate.Code != http.StatusOK {
		t.Fatalf("migrate tenant A = %d body=%s", migrate.Code, migrate.Body.String())
	}
	readA := servedTenantSealRequest(t, srv, tokenA, http.MethodGet, "/api/v1/secrets/store/db/password", "", nil)
	if readA.Code != http.StatusOK || !strings.Contains(readA.Body.String(), "tenant-a-secret") {
		t.Fatalf("read migrated unsealed tenant A = %d body=%s", readA.Code, readA.Body.String())
	}

	queued := servedTenantSealRequest(t, srv, tokenA, http.MethodPost, "/api/v1/platform/tenant-key-domain/seal", "tenant-seal-secret-path", nil)
	if queued.Code != http.StatusAccepted {
		t.Fatalf("queue tenant A seal = %d body=%s", queued.Code, queued.Body.String())
	}
	if n, err := srv.outbox.DispatchScoped(ctx, srv.obHandler, orchestrator.DestinationScope{IncludePrefixes: []string{store.TenantKeyDomainSealDestination}}); err != nil || n != 1 {
		t.Fatalf("dispatch tenant A seal = %d/%v, want 1/nil", n, err)
	}

	locked := servedTenantSealRequest(t, srv, tokenA, http.MethodGet, "/api/v1/secrets/store/db/password", "", nil)
	if locked.Code != http.StatusLocked || !strings.Contains(locked.Body.String(), `"tenant_key_domain_status":"sealed"`) {
		t.Fatalf("sealed tenant A read = %d body=%s", locked.Code, locked.Body.String())
	}
	lockedList := servedTenantSealRequest(t, srv, tokenA, http.MethodGet, "/api/v1/secrets/store", "", nil)
	if lockedList.Code != http.StatusLocked || !strings.Contains(lockedList.Body.String(), `"tenant_key_domain_status":"sealed"`) {
		t.Fatalf("sealed tenant A metadata read = %d body=%s", lockedList.Code, lockedList.Body.String())
	}
	lockedWrite := servedTenantSealRequest(t, srv, tokenA, http.MethodPost, "/api/v1/secrets/store", "tenant-a-write-while-sealed", []byte(`{"name":"after/seal","value":"must-not-write"}`))
	if lockedWrite.Code != http.StatusLocked || !strings.Contains(lockedWrite.Body.String(), `"tenant_key_domain_status":"sealed"`) {
		t.Fatalf("sealed tenant A mutation = %d body=%s", lockedWrite.Code, lockedWrite.Body.String())
	}
	lockedVault := servedTenantSealRequest(t, srv, tokenA, http.MethodGet, "/v1/secret/data/db/password", "", nil)
	if lockedVault.Code != http.StatusLocked || !strings.Contains(lockedVault.Body.String(), "sealed") {
		t.Fatalf("sealed tenant A Vault-compatible read = %d body=%s", lockedVault.Code, lockedVault.Body.String())
	}
	readB := servedTenantSealRequest(t, srv, tokenB, http.MethodGet, "/api/v1/secrets/store/db/password", "", nil)
	if readB.Code != http.StatusOK || !strings.Contains(readB.Body.String(), "tenant-b-secret") {
		t.Fatalf("neighbor tenant B read = %d body=%s", readB.Code, readB.Body.String())
	}

	unseal := servedTenantSealRequest(t, srv, tokenA, http.MethodPost, "/api/v1/platform/tenant-key-domain/unseal", "tenant-unseal-secret-path", nil)
	if unseal.Code != http.StatusOK {
		t.Fatalf("unseal tenant A = %d body=%s", unseal.Code, unseal.Body.String())
	}
	reopened := servedTenantSealRequest(t, srv, tokenA, http.MethodGet, "/api/v1/secrets/store/db/password", "", nil)
	if reopened.Code != http.StatusOK || !strings.Contains(reopened.Body.String(), "tenant-a-secret") {
		t.Fatalf("read unsealed tenant A = %d body=%s", reopened.Code, reopened.Body.String())
	}
	notWritten := servedTenantSealRequest(t, srv, tokenA, http.MethodGet, "/api/v1/secrets/store/after/seal", "", nil)
	if notWritten.Code != http.StatusNotFound || strings.Contains(notWritten.Body.String(), "must-not-write") {
		t.Fatalf("sealed tenant A mutation reached storage = %d body=%s", notWritten.Code, notWritten.Body.String())
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
