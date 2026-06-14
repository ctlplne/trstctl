package crypto

import (
	"bytes"
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
