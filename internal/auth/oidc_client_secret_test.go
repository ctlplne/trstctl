package auth_test

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrets"
	"trstctl.com/trstctl/internal/store"
)

func TestOIDCClientSecretVaultEncryptsAndRoundTrips(t *testing.T) {
	kek, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	t.Cleanup(kek.Destroy)
	fs := &oidcClientSecretMemoryStore{}
	vault := secrets.NewVault(kek, fs)
	plain := []byte("oidc-client-secret-do-not-persist")
	defer secret.Wipe(plain)

	if err := auth.StoreOIDCClientSecret(context.Background(), vault, "tenant-a", "primary", plain); err != nil {
		t.Fatalf("StoreOIDCClientSecret: %v", err)
	}
	if fs.saved.TenantID != "tenant-a" || fs.saved.Scope != auth.OIDCClientSecretScope ||
		fs.saved.Ref != "primary" || fs.saved.Name != auth.OIDCClientSecretName {
		t.Fatalf("stored credential identity = %+v", fs.saved)
	}
	if bytes.Contains(fs.saved.Sealed, plain) {
		t.Fatal("stored OIDC client secret contains plaintext")
	}

	got, err := auth.LoadOIDCClientSecret(context.Background(), vault, "tenant-a", "primary")
	if err != nil {
		t.Fatalf("LoadOIDCClientSecret: %v", err)
	}
	defer secret.Wipe(got)
	if !bytes.Equal(got, plain) {
		t.Fatalf("opened OIDC client secret = %q, want original plaintext", got)
	}
}

type oidcClientSecretMemoryStore struct {
	saved store.Credential
}

func (s *oidcClientSecretMemoryStore) PutCredential(_ context.Context, c store.Credential) error {
	s.saved = c
	return nil
}

func (s *oidcClientSecretMemoryStore) GetCredential(_ context.Context, tenantID, scope, ref, name string) (store.Credential, error) {
	if s.saved.TenantID == tenantID && s.saved.Scope == scope && s.saved.Ref == ref && s.saved.Name == name {
		return s.saved, nil
	}
	return store.Credential{}, store.ErrCredentialNotFound
}
