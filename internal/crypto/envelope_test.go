// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	kek, _ := NewKEK()
	pt := []byte("super-secret-value")
	aad := []byte("tenant1|app/db/password")
	env, err := SealEnvelope(kek, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	// Ciphertext must not contain the plaintext.
	if bytes.Contains(env.Ciphertext, pt) {
		t.Fatal("plaintext leaked into ciphertext")
	}
	got, err := OpenEnvelope(kek, env, aad)
	if err != nil {
		t.Fatalf("OpenEnvelope: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Errorf("round-trip = %q, want %q", got, pt)
	}
}

func TestEnvelopeFailsClosed(t *testing.T) {
	kek, _ := NewKEK()
	aad := []byte("aad")
	env, _ := SealEnvelope(kek, []byte("v"), aad)

	// Wrong KEK.
	other, _ := NewKEK()
	if _, err := OpenEnvelope(other, env, aad); err == nil {
		t.Error("opened with the wrong KEK")
	}
	// Mismatched AAD.
	if _, err := OpenEnvelope(kek, env, []byte("different")); err == nil {
		t.Error("opened with mismatched AAD")
	}
	// Tampered ciphertext.
	bad := env
	bad.Ciphertext = append([]byte(nil), env.Ciphertext...)
	bad.Ciphertext[0] ^= 0xff
	if _, err := OpenEnvelope(kek, bad, aad); err == nil {
		t.Error("opened tampered ciphertext")
	}
}

func TestEnvelopeCarriesVersionAndLegacyDecoder(t *testing.T) {
	kek, _ := NewKEK()
	aad := []byte("tenant1|app/db/password")
	pt := []byte("super-secret-value")

	env, err := SealEnvelope(kek, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	if env.Format != EnvelopeFormat || env.Version != EnvelopeVersion {
		t.Fatalf("envelope metadata = %q v%d, want %q v%d", env.Format, env.Version, EnvelopeFormat, EnvelopeVersion)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range [][]byte{[]byte(`"format"`), []byte(`"version"`), []byte(EnvelopeFormat)} {
		if !bytes.Contains(raw, want) {
			t.Fatalf("marshaled envelope %s does not contain %s", raw, want)
		}
	}

	legacy := env
	legacy.Format = ""
	legacy.Version = 0
	got, err := OpenEnvelope(kek, legacy, aad)
	if err != nil {
		t.Fatalf("OpenEnvelope legacy v1: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("legacy v1 plaintext = %q, want %q", got, pt)
	}

	unknownVersion := env
	unknownVersion.Version = EnvelopeVersion + 1
	if _, err := OpenEnvelope(kek, unknownVersion, aad); err == nil {
		t.Fatal("OpenEnvelope accepted an explicitly unknown envelope version")
	}
	unknownFormat := env
	unknownFormat.Format = "trstctl.crypto.future-envelope"
	if _, err := OpenEnvelope(kek, unknownFormat, aad); err == nil {
		t.Fatal("OpenEnvelope accepted an explicitly unknown envelope format")
	}
}

// TestEnvelopeWipesDEKViaSecretWipe guards CRYPTO-006: the per-secret DEK must be
// zeroized through secret.Wipe (which holds the buffer with runtime.KeepAlive so
// the compiler cannot treat the zeroing stores as dead), not through a bare local
// loop. The earlier envelope.go defined an elidable local zero() and called
// defer zero(dek) — a regression to that form must fail this test. We assert on
// the real source so the guard cannot be satisfied vacuously.
func TestEnvelopeWipesDEKViaSecretWipe(t *testing.T) {
	src, err := os.ReadFile("envelope.go")
	if err != nil {
		t.Fatalf("read envelope.go: %v", err)
	}
	if bytes.Contains(src, []byte("func zero(")) {
		t.Error("envelope.go still defines a local zero() with no runtime.KeepAlive; route DEK wiping through secret.Wipe (CRYPTO-006)")
	}
	if bytes.Contains(src, []byte("defer zero(dek)")) {
		t.Error("envelope.go still wipes the DEK via the elidable local zero(); use secret.Wipe (CRYPTO-006)")
	}
	if !bytes.Contains(src, []byte("secret.Wipe(dek)")) {
		t.Error("envelope.go must wipe the DEK via secret.Wipe (CRYPTO-006)")
	}
}
