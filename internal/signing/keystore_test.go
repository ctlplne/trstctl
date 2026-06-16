package signing_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
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

// TestSignerReloadsHandleFromSharedStoreOnMiss is the RESIL-002 multi-replica
// enabler: two signers (modeling two control-plane replicas' sidecars) share ONE
// sealed key store. Signer B starts BEFORE the issuing-CA key exists, so its in-memory
// map is empty. Signer A then generates + seals the CA key to the shared store. B,
// which never had the key in memory, must RELOAD it from the shared store on the next
// lookup (GetPublicKey/Sign) rather than reporting it missing — so every replica
// converges on the same CA without a restart. This keeps AN-4 intact (the signer only
// touches its own key store; no new surface).
func TestSignerReloadsHandleFromSharedStoreOnMiss(t *testing.T) {
	dir := t.TempDir() // the SHARED sealed key store
	kek := testKEK(t)
	ctx := context.Background()

	// B boots first over the empty shared store: it has no keys yet.
	sB, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek))
	if err != nil {
		t.Fatalf("NewPersistentServer B: %v", err)
	}
	// Sanity: B does not have the handle before it is created.
	if _, err := sB.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: "issuing-ca"}}); err == nil {
		t.Fatal("B unexpectedly has the issuing-ca handle before any key was generated")
	}

	// A boots over the same store and generates + seals the CA key.
	sA, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek))
	if err != nil {
		t.Fatalf("NewPersistentServer A: %v", err)
	}
	pubA := genCA(t, sA)

	// B must now RELOAD the key from the shared store on the next lookup, returning the
	// SAME public key A generated — proving reload-on-miss converges the replicas.
	gotB, err := sB.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: "issuing-ca"}})
	if err != nil {
		t.Fatalf("B GetPublicKey after A sealed the key (reload-on-miss must load it): %v", err)
	}
	if !bytes.Equal(gotB.GetPublicKey(), pubA) {
		t.Fatal("B reloaded a DIFFERENT key than A sealed — replicas would disagree on the CA (RESIL-002)")
	}
	// And B can sign with the reloaded key.
	sig, err := sB.Sign(ctx, &signerpb.SignRequest{
		Handle: &signerpb.KeyHandle{Id: "issuing-ca"},
		Digest: make([]byte, 32),
		Hash:   signerpb.Hash_HASH_SHA256,
	})
	if err != nil || len(sig.GetSignature()) == 0 {
		t.Fatalf("B cannot sign with the reloaded shared CA key: %v", err)
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
