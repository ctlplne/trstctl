package signing_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

func TestLoadOrCreateAuthorizerCreatesStableSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sign-auth.bin")
	authz, err := signing.LoadOrCreateAuthorizer(path)
	if err != nil {
		t.Fatalf("LoadOrCreateAuthorizer create: %v", err)
	}
	defer authz.Destroy()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat created secret: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("secret mode = %o, want 0600", got)
	}
	intent := crypto.SignIntent{KeyHandle: "issuing-ca", Purpose: 1, Hash: crypto.SHA256, Padding: crypto.RSAPKCS1v15, Digest: []byte("digest")}
	token, err := authz.Authorize(intent)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	reloaded, err := signing.LoadOrCreateAuthorizer(path)
	if err != nil {
		t.Fatalf("LoadOrCreateAuthorizer reload: %v", err)
	}
	defer reloaded.Destroy()
	if !reloaded.Verify(intent, token) {
		t.Fatal("reloaded authorizer did not verify token minted by first load")
	}
}

func TestLoadOrCreateAuthorizerRejectsUnsafeExistingFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sign-auth.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x44}, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := signing.LoadOrCreateAuthorizer(path); err == nil {
		t.Fatal("LoadOrCreateAuthorizer accepted an unsafe existing file mode")
	}
}
