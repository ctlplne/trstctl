package crypto_test

import (
	"encoding/hex"
	"testing"

	"certctl.io/certctl/internal/crypto"
)

// TestSHA256Hex pins the digest of the empty input and a known string.
func TestSHA256Hex(t *testing.T) {
	if got := crypto.SHA256Hex(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("SHA256Hex(nil) = %s", got)
	}
	if got := crypto.SHA256Hex([]byte("abc")); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("SHA256Hex(abc) = %s", got)
	}
}

// TestHMACSHA256RFC4231 verifies the keyed-MAC primitive against RFC 4231
// Test Case 2 — the canonical HMAC-SHA256 vector — so the boundary helper the
// SigV4 signer depends on is independently correct, not merely self-consistent
// with our own double.
func TestHMACSHA256RFC4231(t *testing.T) {
	got := hex.EncodeToString(crypto.HMACSHA256([]byte("Jefe"), []byte("what do ya want for nothing?")))
	const want = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	if got != want {
		t.Errorf("HMAC-SHA256 = %s, want %s", got, want)
	}
}

// TestHMACSHA256KeyMatters confirms the MAC depends on the key (a different key
// yields a different tag for the same data).
func TestHMACSHA256KeyMatters(t *testing.T) {
	a := crypto.HMACSHA256([]byte("k1"), []byte("msg"))
	b := crypto.HMACSHA256([]byte("k2"), []byte("msg"))
	if hex.EncodeToString(a) == hex.EncodeToString(b) {
		t.Error("HMAC must differ when the key differs")
	}
}
