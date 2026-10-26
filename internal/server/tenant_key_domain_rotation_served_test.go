// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	authpkg "trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	secretvault "trstctl.com/trstctl/internal/secrets"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// TestServedTenantKeyDomainRotationRewrapsTenantDataAndMovesWrappers drives
// the default-binary composition. After a migrated tenant rotates, its secrets
// and OIDC client secret still open, the stored ciphertext is read back from
// PostgreSQL in the new generation, a replayed request does not rotate twice, a
// second rotation moves the domain onto another configured wrapper, and the
// neighbor tenant (still on the deployment key) can neither rotate nor change.
func TestServedTenantKeyDomainRotationRewrapsTenantDataAndMovesWrappers(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	const rotatingTenant = "55555555-5555-5555-5555-555555555555"
	const neighborTenant = "66666666-6666-6666-6666-666666666666"
	for _, tenant := range []store.Tenant{
		{TenantID: rotatingTenant, Name: "tenant-rotate-served", EventSeq: 1},
		{TenantID: neighborTenant, Name: "tenant-rotate-neighbor", EventSeq: 1},
	} {
		if err := st.UpsertTenant(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	tokenA := seedScopedToken(t, st, rotatingTenant, "keys:read", "keys:write", "secrets:read", "secrets:write")
	tokenB := seedScopedToken(t, st, neighborTenant, "keys:read", "keys:write", "secrets:read", "secrets:write")

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Secrets.EnableAPI = true
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "deployment-kek")
	for id, fill := range map[string]byte{"tenant-rotate-wrapper": 0x5a, "tenant-rotate-wrapper-next": 0x5b} {
		path := filepath.Join(t.TempDir(), id+".key")
		if err := os.WriteFile(path, bytes.Repeat([]byte{fill}, 32), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg.Secrets.TenantSealLocalWrappers = append(cfg.Secrets.TenantSealLocalWrappers,
			config.TenantSealLocalWrapper{ID: id, File: path})
	}
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
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
	vault := secretvault.NewVault(secrets.kek, st)
	if err := authpkg.StoreOIDCClientSecret(ctx, vault, rotatingTenant, "primary", []byte("tenant-a-oidc-secret")); err != nil {
		t.Fatal(err)
	}
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

	for _, request := range []struct {
		token, key string
		body       []byte
	}{
		{tokenA, "tenant-a-rotate-secret", []byte(`{"name":"db/password","value":"tenant-a-secret"}`)},
		{tokenB, "tenant-b-rotate-secret", []byte(`{"name":"db/password","value":"tenant-b-secret"}`)},
	} {
		if rec := servedTenantSealRequest(t, srv, request.token, http.MethodPost, "/api/v1/secrets/store", request.key, request.body); rec.Code != http.StatusCreated {
			t.Fatalf("create secret = %d body=%s", rec.Code, rec.Body.String())
		}
	}
	neighborBefore := servedSecretStoreCiphertext(t, st, neighborTenant)

	if rec := servedTenantSealRequest(t, srv, tokenB, http.MethodPost, "/api/v1/platform/tenant-key-domain/rotate", "tenant-b-rotate", nil); rec.Code != http.StatusConflict {
		t.Fatalf("deployment-key tenant rotate = %d body=%s", rec.Code, rec.Body.String())
	}
	migrate := servedTenantSealRequest(t, srv, tokenA, http.MethodPost,
		"/api/v1/platform/tenant-key-domain/migrate", "tenant-a-migrate-before-rotate",
		[]byte(`{"wrapper_kind":"local_file","wrapper_id":"tenant-rotate-wrapper"}`))
	if migrate.Code != http.StatusOK {
		t.Fatalf("migrate = %d body=%s", migrate.Code, migrate.Body.String())
	}
	migrated, err := deps.TenantKeyDomains.Status(ctx, rotatingTenant)
	if err != nil {
		t.Fatal(err)
	}

	first := servedTenantSealRequest(t, srv, tokenA, http.MethodPost, "/api/v1/platform/tenant-key-domain/rotate", "tenant-a-rotate-1", nil)
	if first.Code != http.StatusOK {
		t.Fatalf("rotate = %d body=%s", first.Code, first.Body.String())
	}
	var status api.TenantKeyDomainStatus
	if err := json.Unmarshal(first.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Generation != 2 || status.State != store.TenantKeyDomainStateUnsealed ||
		status.OperationKind != store.TenantKeyOperationRotate || status.WrapperID != "tenant-rotate-wrapper" ||
		status.RotatedAt == nil || status.NextGeneration != 0 {
		t.Fatalf("rotate status = %+v", status)
	}
	replay := servedTenantSealRequest(t, srv, tokenA, http.MethodPost, "/api/v1/platform/tenant-key-domain/rotate", "tenant-a-rotate-1", nil)
	if replay.Code != http.StatusOK || !bytes.Equal(replay.Body.Bytes(), first.Body.Bytes()) {
		t.Fatalf("replayed rotate = %d body=%s, want the byte-identical first response", replay.Code, replay.Body.String())
	}
	rotated, err := deps.TenantKeyDomains.Status(ctx, rotatingTenant)
	if err != nil || rotated.Generation != 2 || bytes.Equal(rotated.WrappedDomainKEK, migrated.WrappedDomainKEK) {
		t.Fatalf("a replay rotated again or the domain KEK did not change: %+v err=%v", rotated, err)
	}
	servedRequireSecretGeneration(t, st, rotatingTenant, rotated.DomainID, 2)
	servedRequireTenantSecretsOpen(t, srv, tokenA, st, secrets, deps, rotatingTenant)

	moved := servedTenantSealRequest(t, srv, tokenA, http.MethodPost, "/api/v1/platform/tenant-key-domain/rotate", "tenant-a-rotate-2",
		[]byte(`{"wrapper_kind":"local_file","wrapper_id":"tenant-rotate-wrapper-next"}`))
	if moved.Code != http.StatusOK {
		t.Fatalf("rotate onto the next wrapper = %d body=%s", moved.Code, moved.Body.String())
	}
	if err := json.Unmarshal(moved.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Generation != 3 || status.WrapperID != "tenant-rotate-wrapper-next" {
		t.Fatalf("moved status = %+v", status)
	}
	servedRequireSecretGeneration(t, st, rotatingTenant, rotated.DomainID, 3)
	servedRequireTenantSecretsOpen(t, srv, tokenA, st, secrets, deps, rotatingTenant)

	if got := servedSecretStoreCiphertext(t, st, neighborTenant); !bytes.Equal(got, neighborBefore) {
		t.Fatal("the neighbor tenant's secret ciphertext changed during tenant A rotations")
	}
	if rec := servedTenantSealRequest(t, srv, tokenB, http.MethodGet, "/api/v1/secrets/store/db/password", "", nil); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "tenant-b-secret") {
		t.Fatalf("neighbor read = %d body=%s", rec.Code, rec.Body.String())
	}
}

// servedRequireTenantSecretsOpen reads tenant A's secret through the API and its
// OIDC client secret through the tenant cipher.
func servedRequireTenantSecretsOpen(t *testing.T, srv *Server, token string, st *store.Store, secrets runSecrets, deps Deps, tenantID string) {
	t.Helper()
	if rec := servedTenantSealRequest(t, srv, token, http.MethodGet, "/api/v1/secrets/store/db/password", "", nil); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "tenant-a-secret") {
		t.Fatalf("read after rotation = %d body=%s", rec.Code, rec.Body.String())
	}
	oidc, err := buildOIDCClientSecretSource(config.OIDC{ClientSecretTenant: tenantID, ClientSecretRef: "primary"}, st, secrets.kek, deps.TenantCrypto)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := oidc(context.Background())
	defer secret.Wipe(opened)
	if err != nil || !bytes.Equal(opened, []byte("tenant-a-oidc-secret")) {
		t.Fatalf("OIDC client secret after rotation did not open: %v", err)
	}
}

// servedRequireSecretGeneration reads the stored secret ciphertext straight from
// PostgreSQL and checks the generation its container is labeled with.
func servedRequireSecretGeneration(t *testing.T, st *store.Store, tenantID, domainID string, generation int64) {
	t.Helper()
	want, err := tenantseal.DomainBinding(tenantID, domainID, generation)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := seal.Domain(servedSecretStoreCiphertext(t, st, tenantID)); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("stored secret label = %q, %v; want generation %d", got, err, generation)
	}
}

func servedSecretStoreCiphertext(t *testing.T, st *store.Store, tenantID string) []byte {
	t.Helper()
	var sealed []byte
	if err := st.WithTenant(context.Background(), tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT sealed FROM secret_store WHERE tenant_id = $1 AND octet_length(sealed) > 0 LIMIT 1`, tenantID).Scan(&sealed)
	}); err != nil {
		t.Fatal(err)
	}
	return sealed
}
