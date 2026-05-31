package signing_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"certctl.io/certctl/internal/crypto/seal"
	"certctl.io/certctl/internal/signing"
	signerpb "certctl.io/certctl/internal/signing/proto"
)

func testKEK(t *testing.T) *seal.LocalKEK {
	t.Helper()
	// Generate the KEK through the crypto boundary (AN-3: no crypto/rand here).
	raw, err := seal.GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}
	k, err := seal.NewLocalKEK(raw)
	if err != nil {
		t.Fatalf("NewLocalKEK: %v", err)
	}
	t.Cleanup(k.Destroy)
	return k
}

func genCA(t *testing.T, s *signing.Server) []byte {
	t.Helper()
	gen, err := s.GenerateKey(context.Background(), &signerpb.GenerateKeyRequest{
		Algorithm:   signerpb.Algorithm_ALGORITHM_ECDSA_P256,
		RequestedId: "issuing-ca",
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return gen.GetPublicKey()
}

// TestSignerPersistsKeysAcrossRestart is the R3.2 disconfirming test for the
// silent-CA-rotation finding: a key generated in a persistent signer survives a
// restart (a fresh Server over the same sealed key store) with the SAME public
// key, and can still sign. Before R3.2 the signer held keys only in memory, so a
// restart rotated the CA.
func TestSignerPersistsKeysAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK(t)
	ctx := context.Background()

	// Boot 1: generate the issuing CA key in a persistent signer.
	s1, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek))
	if err != nil {
		t.Fatalf("NewPersistentServer (boot 1): %v", err)
	}
	pub1 := genCA(t, s1)

	// Boot 2: a fresh signer over the SAME sealed key store (the restart).
	s2, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek))
	if err != nil {
		t.Fatalf("NewPersistentServer (boot 2): %v", err)
	}

	got, err := s2.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: "issuing-ca"}})
	if err != nil {
		t.Fatalf("GetPublicKey after restart: %v", err)
	}
	if !bytes.Equal(got.GetPublicKey(), pub1) {
		t.Fatal("CA public key changed across restart — the CA silently rotated")
	}

	// The reloaded CA key still signs.
	sig, err := s2.Sign(ctx, &signerpb.SignRequest{
		Handle: &signerpb.KeyHandle{Id: "issuing-ca"},
		Digest: make([]byte, 32),
		Hash:   signerpb.Hash_HASH_SHA256,
	})
	if err != nil || len(sig.GetSignature()) == 0 {
		t.Fatalf("reloaded CA key cannot sign: %v", err)
	}
}

// TestSignerKeyBackupRestore: the sealed key store is the CA-key backup. Copying
// it into a fresh location restores a working signer that signs with the same key.
func TestSignerKeyBackupRestore(t *testing.T) {
	src := t.TempDir()
	kek := testKEK(t)

	s1, err := signing.NewPersistentServer(signing.NewKeyStore(src, kek))
	if err != nil {
		t.Fatalf("NewPersistentServer: %v", err)
	}
	pub := genCA(t, s1)

	// "Back up" by copying every sealed key file to a new directory.
	dst := t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o600); err != nil {
			t.Fatalf("write %s: %v", e.Name(), err)
		}
	}

	// Restore into a fresh signer from the backup directory (same KEK).
	restored, err := signing.NewPersistentServer(signing.NewKeyStore(dst, kek))
	if err != nil {
		t.Fatalf("NewPersistentServer (restore): %v", err)
	}
	got, err := restored.GetPublicKey(context.Background(), &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: "issuing-ca"}})
	if err != nil {
		t.Fatalf("GetPublicKey after restore: %v", err)
	}
	if !bytes.Equal(got.GetPublicKey(), pub) {
		t.Error("restored CA public key differs from the backed-up key")
	}
}
