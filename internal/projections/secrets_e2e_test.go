package projections_test

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"certctl.io/certctl/internal/secrets"
)

// TestSealedCredentialsAtRestAndTenantIsolated is the R3.1 disconfirming test for
// the secrets findings: a CA/connector credential persisted through the Vault is
// (1) stored encrypted at rest — the raw column never holds the plaintext — and
// (2) tenant-isolated by row-level security (AN-1). Before R3.1 such credentials
// had no sealed home at all.
func TestSealedCredentialsAtRestAndTenantIsolated(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()

	kek, err := secrets.LoadOrCreateKEK(filepath.Join(t.TempDir(), "kek.bin"))
	if err != nil {
		t.Fatalf("LoadOrCreateKEK: %v", err)
	}
	defer kek.Destroy()
	vault := secrets.NewVault(kek, st)

	plaintext := []byte("f5-admin-password-9c4b21")
	if err := vault.Put(ctx, tenantA, "connector", "target-1", "password", plaintext); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// At rest: read the raw column (as the privileged pool role) and confirm it is
	// ciphertext, not the plaintext.
	var sealed []byte
	if err := st.Pool().QueryRow(ctx,
		"SELECT sealed FROM credentials WHERE tenant_id = $1 AND ref = $2", tenantA, "target-1").
		Scan(&sealed); err != nil {
		t.Fatalf("read raw sealed column: %v", err)
	}
	if len(sealed) == 0 {
		t.Fatal("no sealed bytes stored")
	}
	if bytes.Contains(sealed, plaintext) {
		t.Fatal("the credentials table holds the plaintext; it is not encrypted at rest")
	}

	// The owning tenant reads it back through the vault.
	got, err := vault.Get(ctx, tenantA, "connector", "target-1", "password")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("vault round-trip mismatch: got %q want %q", got, plaintext)
	}

	// Tenant isolation: another tenant cannot read it (RLS fail-closed).
	if _, err := vault.Get(ctx, tenantB, "connector", "target-1", "password"); err == nil {
		t.Error("tenant B read tenant A's sealed credential; RLS not enforced")
	}
}
