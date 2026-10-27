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
	"testing"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
	transitpkg "trstctl.com/trstctl/internal/transit"
)

// TestServedTenantKeyDomainMigrationAndRotationRewrapTransitKeyrings: a
// tenant's shared transit keyring is sealed through its key domain like every
// other tenant secret, so migrating the tenant into its own domain and
// rotating that domain re-wrap the stored keyring row too. A replica that
// starts afterwards (a second transit service on the same database, with
// nothing cached) still decrypts what was encrypted before the migration.
func TestServedTenantKeyDomainMigrationAndRotationRewrapTransitKeyrings(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	const tenantID = "57575757-5757-4575-8575-575757575757"
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "tenant-transit-domain", EventSeq: 1}); err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, st, tenantID, "keys:read", "keys:write")

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "deployment-kek")
	wrapperPath := filepath.Join(t.TempDir(), "transit-domain-wrapper.key")
	if err := os.WriteFile(wrapperPath, bytes.Repeat([]byte{0x6c}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Secrets.TenantSealLocalWrappers = []config.TenantSealLocalWrapper{{ID: "transit-domain-wrapper", File: wrapperPath}}
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

	if rec := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/transit/keys", "transit-domain-create",
		[]byte(`{"name":"payments","kind":"aead"}`)); rec.Code != http.StatusCreated {
		t.Fatalf("create transit key = %d body=%s", rec.Code, rec.Body.String())
	}
	plaintext := []byte("tokenized-before-the-migration")
	body, err := json.Marshal(map[string]any{"key": "payments", "plaintext": plaintext})
	if err != nil {
		t.Fatal(err)
	}
	rec := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/transit/encrypt", "transit-domain-encrypt", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("encrypt = %d body=%s", rec.Code, rec.Body.String())
	}
	var encrypted struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &encrypted); err != nil || encrypted.Ciphertext == "" {
		t.Fatalf("encrypt response %s: %v", rec.Body.String(), err)
	}

	if rec := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/platform/tenant-key-domain/migrate", "transit-domain-migrate",
		[]byte(`{"wrapper_kind":"local_file","wrapper_id":"transit-domain-wrapper"}`)); rec.Code != http.StatusOK {
		t.Fatalf("migrate = %d body=%s", rec.Code, rec.Body.String())
	}
	servedRequireTransitKeyringGeneration(t, st, deps, tenantID)
	servedRequireFreshReplicaDecrypts(t, st, log, deps, secrets, tenantID, encrypted.Ciphertext, plaintext)

	if rec := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/platform/tenant-key-domain/rotate", "transit-domain-rotate", nil); rec.Code != http.StatusOK {
		t.Fatalf("rotate = %d body=%s", rec.Code, rec.Body.String())
	}
	servedRequireTransitKeyringGeneration(t, st, deps, tenantID)
	servedRequireFreshReplicaDecrypts(t, st, log, deps, secrets, tenantID, encrypted.Ciphertext, plaintext)
}

// servedRequireTransitKeyringGeneration reads the stored keyring row back from
// PostgreSQL and requires it to carry the domain's current generation label.
func servedRequireTransitKeyringGeneration(t *testing.T, st *store.Store, deps Deps, tenantID string) {
	t.Helper()
	ctx := context.Background()
	domain, err := deps.TenantKeyDomains.Status(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	want, err := tenantseal.DomainBinding(tenantID, domain.DomainID, domain.Generation)
	if err != nil {
		t.Fatal(err)
	}
	sealed, _, found, err := st.LoadTransitKeyring(ctx, tenantID)
	if err != nil || !found {
		t.Fatalf("load the transit keyring row: found=%v err=%v", found, err)
	}
	label, err := seal.Domain(sealed)
	if err != nil || !bytes.Equal(label, want) {
		t.Fatalf("transit keyring row domain = %q (err %v), want generation %d label %q", label, err, domain.Generation, want)
	}
}

// servedRequireFreshReplicaDecrypts starts a second transit service on the
// same database, as a replica that starts after the change would, and
// decrypts the earlier ciphertext with nothing cached.
func servedRequireFreshReplicaDecrypts(
	t *testing.T,
	st *store.Store,
	log *events.Log,
	deps Deps,
	secrets runSecrets,
	tenantID, ciphertext string,
	want []byte,
) {
	t.Helper()
	replica := transitpkg.NewService(audit.NewAuditor(log))
	t.Cleanup(replica.Destroy)
	if err := replica.SetSharedPersistence(st, transitTenantSealer{access: deps.TenantCrypto, legacy: secrets.kek}); err != nil {
		t.Fatal(err)
	}
	got, err := replica.Decrypt(context.Background(), tenantID, "payments", ciphertext, nil)
	defer secret.Wipe(got)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("a fresh replica could not decrypt after the key-domain change: %v", err)
	}
}
