package crypto_test

import (
	"bytes"
	"testing"

	"certctl.io/certctl/internal/crypto"
)

// TestLockedKeyPKCS8RoundTrip: a locked key can be exported as PKCS#8 (for sealed
// persistence) and re-imported into an identical key that still signs — the basis
// for surviving a signer restart (R3.2).
func TestLockedKeyPKCS8RoundTrip(t *testing.T) {
	ls, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}
	defer ls.Destroy()

	der, err := ls.PKCS8()
	if err != nil {
		t.Fatalf("PKCS8: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("PKCS8 returned empty DER")
	}

	restored, err := crypto.LockedKeyFromPKCS8(der)
	if err != nil {
		t.Fatalf("LockedKeyFromPKCS8: %v", err)
	}
	defer restored.Destroy()

	if !bytes.Equal(restored.Public().DER, ls.Public().DER) {
		t.Error("restored public key differs from the original (not the same key)")
	}
	if restored.Algorithm() != ls.Algorithm() {
		t.Errorf("restored algorithm = %v, want %v", restored.Algorithm(), ls.Algorithm())
	}

	// The reconstructed key can actually sign.
	digest := make([]byte, 32)
	if _, err := restored.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatalf("restored key cannot sign: %v", err)
	}
}
