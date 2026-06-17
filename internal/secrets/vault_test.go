package secrets_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/secrets"
	"trstctl.com/trstctl/internal/store"
)

// fakeStore is an in-memory CredentialStore for unit-testing the Vault without a
// database. It records exactly the bytes the Vault asks it to persist.
type fakeStore struct {
	rows map[string]store.Credential
}

func newFakeStore() *fakeStore { return &fakeStore{rows: map[string]store.Credential{}} }

func key(tenant, scope, ref, name string) string {
	return tenant + "|" + scope + "|" + ref + "|" + name
}

func (f *fakeStore) PutCredential(_ context.Context, c store.Credential) error {
	f.rows[key(c.TenantID, c.Scope, c.Ref, c.Name)] = c
	return nil
}

func (f *fakeStore) GetCredential(_ context.Context, tenant, scope, ref, name string) (store.Credential, error) {
	c, ok := f.rows[key(tenant, scope, ref, name)]
	if !ok {
		return store.Credential{}, store.ErrCredentialNotFound
	}
	return c, nil
}

// TestVaultStoresSealedAndReadsBack: the Vault seals on Put (so the store only
// ever sees ciphertext) and opens on Get.
func TestVaultStoresSealedAndReadsBack(t *testing.T) {
	kek := loadKEK(t)
	fs := newFakeStore()
	v := secrets.NewVault(kek, fs)
	ctx := context.Background()

	plaintext := []byte("digicert-api-key-abc123")
	if err := v.Put(ctx, "tenant-A", "issuer", "issuer-1", "api_key", plaintext); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// What landed in the store must be ciphertext, not the plaintext.
	stored := fs.rows[key("tenant-A", "issuer", "issuer-1", "api_key")]
	if len(stored.Sealed) == 0 {
		t.Fatal("nothing sealed was stored")
	}
	if bytes.Contains(stored.Sealed, plaintext) {
		t.Fatal("the store holds the plaintext credential; it is not encrypted at rest")
	}

	got, err := v.Get(ctx, "tenant-A", "issuer", "issuer-1", "api_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Get returned %q, want %q", got, plaintext)
	}
}

// TestVaultGetMissing: a missing credential is a clean not-found, not a panic.
func TestVaultGetMissing(t *testing.T) {
	v := secrets.NewVault(loadKEK(t), newFakeStore())
	if _, err := v.Get(context.Background(), "tenant-A", "issuer", "nope", "api_key"); err == nil {
		t.Fatal("Get of a missing credential should error")
	}
}

// TestLoadOrCreateKEKIsStableAndPrivate: the KEK file is created 0600 and is
// stable across loads (so sealed data stays openable across restarts).
func TestLoadOrCreateKEKIsStableAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kek.bin")

	k1, err := secrets.LoadOrCreateKEK(path)
	if err != nil {
		t.Fatalf("LoadOrCreateKEK (create): %v", err)
	}
	defer k1.Destroy()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat kek: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("kek file mode = %o, want 600", perm)
	}

	// A second load yields a KEK that opens what the first sealed (same key).
	k2, err := secrets.LoadOrCreateKEK(path)
	if err != nil {
		t.Fatalf("LoadOrCreateKEK (load): %v", err)
	}
	defer k2.Destroy()

	fs := newFakeStore()
	ctx := context.Background()
	if err := secrets.NewVault(k1, fs).Put(ctx, "t", "s", "r", "n", []byte("persisted")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := secrets.NewVault(k2, fs).Get(ctx, "t", "s", "r", "n")
	if err != nil {
		t.Fatalf("Get with reloaded KEK: %v", err)
	}
	if string(got) != "persisted" {
		t.Errorf("reloaded KEK opened to %q, want \"persisted\"", got)
	}
}

func TestLoadOrCreateKEKRejectsUnsafeExistingFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kek.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x42}, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.LoadOrCreateKEK(path); err == nil {
		t.Fatal("LoadOrCreateKEK accepted an unsafe existing file mode")
	}
}

func TestLoadOrCreateAuthSecretIsStableAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.bin")

	first, err := secrets.LoadOrCreateAuthSecret(path)
	if err != nil {
		t.Fatalf("LoadOrCreateAuthSecret create: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat auth secret: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("auth secret mode = %o, want 0600", got)
	}
	second, err := secrets.LoadOrCreateAuthSecret(path)
	if err != nil {
		t.Fatalf("LoadOrCreateAuthSecret reload: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("auth secret was not stable across reload")
	}
}

func TestLoadOrCreateAuthSecretRejectsUnsafeExistingFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x33}, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.LoadOrCreateAuthSecret(path); err == nil {
		t.Fatal("LoadOrCreateAuthSecret accepted an unsafe existing file mode")
	}
}

func loadKEK(t *testing.T) *secrets.KEK {
	t.Helper()
	k, err := secrets.LoadOrCreateKEK(filepath.Join(t.TempDir(), "kek.bin"))
	if err != nil {
		t.Fatalf("LoadOrCreateKEK: %v", err)
	}
	t.Cleanup(k.Destroy)
	return k
}
