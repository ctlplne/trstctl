package seal_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
)

func newKEK(t *testing.T) *seal.LocalKEK {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	k, err := seal.NewLocalKEK(raw)
	if err != nil {
		t.Fatalf("NewLocalKEK: %v", err)
	}
	t.Cleanup(k.Destroy)
	return k
}

// TestSealOpenRoundTrip: a sealed credential opens back to the original under the
// same KEK.
func TestSealOpenRoundTrip(t *testing.T) {
	kek := newKEK(t)
	plaintext := []byte("super-secret-ca-api-key-0123456789")

	sealed, err := seal.Seal(kek, plaintext, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := seal.Open(kek, sealed, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

// TestSealedIsNotPlaintext: the at-rest blob is ciphertext — the plaintext must
// not appear in it (this is the "encrypted at rest" guarantee).
func TestSealedIsNotPlaintext(t *testing.T) {
	kek := newKEK(t)
	plaintext := []byte("P@ssw0rd-do-not-store-in-the-clear")
	sealed, err := seal.Seal(kek, plaintext, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed, plaintext) {
		t.Fatal("sealed blob contains the plaintext; it is not encrypted at rest")
	}
	// Sealing the same value twice yields different blobs (fresh DEK + nonces).
	sealed2, _ := seal.Seal(kek, plaintext, nil)
	if bytes.Equal(sealed, sealed2) {
		t.Error("two seals of the same plaintext are identical; nonce/DEK is not random")
	}
}

// TestOpenRejectsTamper: AEAD integrity — any bit flip in the sealed blob fails
// to open.
func TestOpenRejectsTamper(t *testing.T) {
	kek := newKEK(t)
	sealed, err := seal.Seal(kek, []byte("rotate-me"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := seal.Open(kek, tampered, nil); err == nil {
		t.Fatal("Open accepted a tampered blob; integrity not enforced")
	}
}

// TestOpenRejectsWrongKEK: a blob sealed under one KEK cannot be opened under
// another.
func TestOpenRejectsWrongKEK(t *testing.T) {
	k1 := newKEK(t)
	k2 := newKEK(t)
	sealed, err := seal.Seal(k1, []byte("client-secret"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := seal.Open(k2, sealed, nil); err == nil {
		t.Fatal("Open succeeded under the wrong KEK")
	}
}

// TestAADBinds: associated data binds the ciphertext to a context; opening with
// different AAD fails (prevents swapping a sealed credential into another row).
func TestAADBinds(t *testing.T) {
	kek := newKEK(t)
	sealed, err := seal.Seal(kek, []byte("token"), []byte("tenant-A/issuer-1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := seal.Open(kek, sealed, []byte("tenant-B/issuer-1")); err == nil {
		t.Fatal("Open succeeded with mismatched AAD; binding not enforced")
	}
	if _, err := seal.Open(kek, sealed, []byte("tenant-A/issuer-1")); err != nil {
		t.Fatalf("Open with correct AAD failed: %v", err)
	}
}

// TestErrorDoesNotLeakPlaintext: a failed Open must not echo the plaintext (no
// secret in errors).
func TestErrorDoesNotLeakPlaintext(t *testing.T) {
	kek := newKEK(t)
	plaintext := []byte("leak-canary-7f3a")
	sealed, _ := seal.Seal(kek, plaintext, nil)
	sealed[len(sealed)-1] ^= 0xFF
	_, err := seal.Open(kek, sealed, nil)
	if err == nil {
		t.Fatal("expected an error opening a tampered blob")
	}
	if bytes.Contains([]byte(err.Error()), plaintext) {
		t.Errorf("error message leaks the plaintext: %v", err)
	}
}

// TestNewLocalKEKRejectsWrongSize: the local KEK must be a 256-bit key.
func TestNewLocalKEKRejectsWrongSize(t *testing.T) {
	if _, err := seal.NewLocalKEK(make([]byte, 16)); err == nil {
		t.Error("NewLocalKEK accepted a 16-byte key; want 32-byte (AES-256) requirement")
	}
}

// TestOpenDispatchesOnVersionByte is the SCHEMA-005 acceptance: Open reads the
// version byte and dispatches to that version's reader, rather than hard-rejecting
// anything that is not the single current version. The v1 blob round-trips; a blob
// whose version byte is mutated to an unknown value is rejected with ErrFormat (the
// reader does not guess a layout). When a future v2 is added, the unknown-version
// rows here become the v2 round-trip and the table extends — proving Open is
// version-DISPATCHED, not version-gated.
func TestOpenDispatchesOnVersionByte(t *testing.T) {
	kek := newKEK(t)
	plaintext := []byte("dispatch-me-by-version")
	v1, err := seal.Seal(kek, plaintext, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// The version byte sits immediately after the 4-byte magic "CSL1".
	const versionOffset = 4
	if v1[versionOffset] != 1 {
		t.Fatalf("expected v1 blob to carry version byte 1, got %d", v1[versionOffset])
	}

	cases := []struct {
		name       string
		version    byte
		wantOpenOK bool
	}{
		{"v1 round-trips", 1, true},
		{"unknown v2 rejected", 2, false},
		{"unknown v0 rejected", 0, false},
		{"unknown v255 rejected", 255, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blob := append([]byte(nil), v1...)
			blob[versionOffset] = tc.version
			got, err := seal.Open(kek, blob, nil)
			if tc.wantOpenOK {
				if err != nil {
					t.Fatalf("Open(v%d) failed: %v", tc.version, err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("Open(v%d) = %q, want %q", tc.version, got, plaintext)
				}
				return
			}
			// Unknown version: must be rejected as a format error (fail closed), and
			// must NOT be silently decoded against the v1 layout.
			if err == nil {
				t.Fatalf("Open(v%d) accepted an unknown version; want ErrFormat", tc.version)
			}
			if !errors.Is(err, seal.ErrFormat) {
				t.Fatalf("Open(v%d) error = %v, want ErrFormat", tc.version, err)
			}
		})
	}
}

// TestOpenRejectsTruncatedVersionedHeader: a blob too short to even carry the
// version byte is a format error, not a panic.
func TestOpenRejectsTruncatedVersionedHeader(t *testing.T) {
	kek := newKEK(t)
	if _, err := seal.Open(kek, []byte("CSL1"), nil); !errors.Is(err, seal.ErrFormat) {
		t.Fatalf("Open of a magic-only blob = %v, want ErrFormat", err)
	}
}
