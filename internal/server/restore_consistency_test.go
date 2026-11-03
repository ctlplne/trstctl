// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secrets"
	"trstctl.com/trstctl/internal/store"
)

func selfSignedCAPEM(t *testing.T, key *crypto.LockedSigner, cn string) []byte {
	t.Helper()
	der, err := crypto.SelfSignedCACert(key, cn, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// The key check reads each CA key the restored deployment relies on through
// the restored signer and refuses one its certificate does not certify.
func TestRestoredKeysMustBeTheKeysTheirCertificatesCertify(t *testing.T) {
	ctx := t.Context()
	st := newServerTestStore(t)
	const tenantID = "6f1d2c3b-4a5e-4f60-8172-93a4b5c6d7e8"
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "Restore keys"}); err != nil {
		t.Fatal(err)
	}
	issuing, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	tenantCA, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "issuing-ca.crt")
	if err := os.WriteFile(caFile, selfSignedCAPEM(t, issuing, "Restored issuing CA"), 0o600); err != nil {
		t.Fatal(err)
	}
	authority, err := st.InsertCAAuthority(ctx, store.CAAuthority{
		TenantID: tenantID, CommonName: "Restored tenant CA", Kind: "root", Status: "active",
		CertificatePEM: string(selfSignedCAPEM(t, tenantCA, "Restored tenant CA")), SignerHandle: "tenant-ca-restore-proof", Serial: "0a246001",
	})
	if err != nil {
		t.Fatal(err)
	}
	// A superseded authority whose key was destroyed is not required.
	if _, err := st.InsertCAAuthority(ctx, store.CAAuthority{
		TenantID: tenantID, CommonName: "Retired tenant CA", Kind: "root", Status: "superseded",
		CertificatePEM: string(selfSignedCAPEM(t, other, "Retired tenant CA")), SignerHandle: "tenant-ca-destroyed", Serial: "0a246002",
	}); err != nil {
		t.Fatal(err)
	}
	held := map[string]crypto.PublicKey{issuingCAHandle: issuing.Public(), "tenant-ca-restore-proof": tenantCA.Public()}
	lookup := func(_ context.Context, handle string) (crypto.PublicKey, error) {
		if public, ok := held[handle]; ok {
			return public, nil
		}
		return crypto.PublicKey{}, fmt.Errorf("handle %q not found", handle)
	}
	if n, err := verifyRestoredKeys(ctx, caFile, st, lookup); err != nil || n != 2 {
		t.Fatalf("consistent keys: verified %d, %v; want 2", n, err)
	}

	held["tenant-ca-restore-proof"] = other.Public()
	if _, err := verifyRestoredKeys(ctx, caFile, st, lookup); err == nil || !strings.Contains(err.Error(), authority.ID) {
		t.Fatalf("a tenant CA whose signer key is another key: %v; want a refusal naming %s", err, authority.ID)
	}
	held["tenant-ca-restore-proof"] = tenantCA.Public()
	delete(held, issuingCAHandle)
	if _, err := verifyRestoredKeys(ctx, caFile, st, lookup); err == nil || !strings.Contains(err.Error(), "the issuing CA") {
		t.Fatalf("an issuing CA whose key the signer does not hold: %v", err)
	}
}

// The secret check opens every stored value, current and retained, under the
// restored keys, and refuses one that does not open.
func TestRestoredSecretsMustOpenUnderTheRestoredKeys(t *testing.T) {
	ctx := t.Context()
	st := newServerTestStore(t)
	cfg := config.Default()
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "deployment-kek.bin")
	kek, err := secrets.LoadOrCreateKEK(cfg.Secrets.KEKFile)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, access, _, err := idempotencyResultProtectionFromConfig(cfg.Secrets, st, kek, nil)
	if err != nil {
		t.Fatal(err)
	}
	const tenantID = "7a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9"
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "Restore secrets"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"db-password", "api-key"} {
		sealed, err := sealTenantValue(ctx, access, nil, tenantID, []byte("value of "+name), []byte(tenantID+"/secret-store/"+name))
		if err != nil {
			t.Fatal(err)
		}
		seedApplicationSecretFixture(t, st, tenantID, name, sealed)
	}
	kek.Destroy()

	// A tenant that sealed its own key domain keeps its secrets closed by
	// design: counted, not opened, not a failure.
	const sealedTenant = "9c4d5e6f-7081-4293-a4b5-c6d7e8f90a12"
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: sealedTenant, Name: "Sealed by its owner"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SystemPool().Exec(ctx, `INSERT INTO tenant_key_domains
		(tenant_id, domain_id, generation, protection_mode, state, wrapper_kind, wrapper_id, wrapped_domain_kek,
		 operation_id, operation_kind, operation_status, legacy_history_exposure, sealed_at,
		 last_transition_event_id, last_transition_type, last_transition_sequence, last_transition_at, created_at, updated_at)
		VALUES ($1, gen_random_uuid(), 1, 'tenant_domain', 'sealed', 'local_file', 'owner-wrapper', '\x01',
		 gen_random_uuid(), 'seal', 'completed', 'none', now(), 'seal-proof', 'tenant.key_domain.sealed', 1, now(), now(), now())`, sealedTenant); err != nil {
		t.Fatal(err)
	}
	seedApplicationSecretFixture(t, st, sealedTenant, "kept-closed", []byte("not openable without its owner"))

	opened, sealedTenants, err := verifyRestoredSecrets(ctx, cfg, st, nil)
	if err != nil || opened != 4 || sealedTenants != 1 {
		t.Fatalf("consistent secrets: opened %d, sealed tenants %d, %v; want 4 (two current, two versions) and 1", opened, sealedTenants, err)
	}

	// One byte of one retained version changed.
	if _, err := st.SystemPool().Exec(ctx, `UPDATE secret_store_versions
		SET sealed = set_byte(sealed, length(sealed)-1, get_byte(sealed, length(sealed)-1) # 1)
		WHERE tenant_id = $1 AND name = 'api-key'`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyRestoredSecrets(ctx, cfg, st, nil); err == nil || !strings.Contains(err.Error(), `"api-key"`) {
		t.Fatalf("a retained version whose bytes changed: %v; want a refusal naming api-key", err)
	}

	// The KEK the backup was sealed under is not the one restored.
	other := config.Default()
	other.Secrets.KEKFile = filepath.Join(t.TempDir(), "other-kek.bin")
	if k, err := secrets.LoadOrCreateKEK(other.Secrets.KEKFile); err == nil {
		k.Destroy()
	}
	if _, _, err := verifyRestoredSecrets(ctx, other, st, nil); err == nil {
		t.Fatal("secrets opened under a KEK they were not sealed under")
	}
}

// The event check compares the restored log with the backup's record for
// record and refuses a log that holds an event the backup does not.
func TestRestoredEventsMustMatchTheBackupRecordForRecord(t *testing.T) {
	ctx := context.Background()
	nats := startBackupTestNATS(t)
	cfg := config.Default()
	cfg.NATS = config.NATS{Mode: config.NATSExternal, URL: nats.ClientURL(), Replicas: 1, AllowSingleReplica: true}
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "deployment-kek.bin")
	if k, err := secrets.LoadOrCreateKEK(cfg.Secrets.KEKFile); err == nil {
		k.Destroy()
	}
	log, err := events.Open(ctx, cfg.NATS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	const tenantID = "8b3c4d5e-6f70-4182-93a4-b5c6d7e8f901"
	for i := 1; i <= 2; i++ {
		if _, err := log.Append(ctx, events.Event{
			ID: fmt.Sprintf("restore-proof-%d", i), Type: projections.EventTenantRegistered,
			TenantID: tenantID, SchemaVersion: 1, Time: time.Now().UTC(), Data: []byte(`{"name":"Restore events"}`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	key, err := backupIntegrityKey(cfg)
	if err != nil || len(key) == 0 {
		t.Fatalf("backup integrity key: %v", err)
	}
	f, err := os.CreateTemp(t.TempDir(), "events-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	if _, err := backup.WriteLogWithKey(ctx, log, f, key); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	if n, err := verifyRestoredEvents(ctx, cfg, log, path, nil); err != nil || n != 2 {
		t.Fatalf("a log that is the backup: verified %d, %v; want 2", n, err)
	}
	if _, err := log.Append(ctx, events.Event{
		ID: "restore-proof-extra", Type: projections.EventTenantRegistered,
		TenantID: tenantID, SchemaVersion: 1, Time: time.Now().UTC(), Data: []byte(`{"name":"Not in the backup"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyRestoredEvents(ctx, cfg, log, path, nil); err == nil {
		t.Fatal("a log with an event the backup does not hold verified")
	}
}
