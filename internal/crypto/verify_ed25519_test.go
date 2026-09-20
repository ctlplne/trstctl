// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"encoding/pem"
	"testing"
)

// TestEd25519SignVerifyRoundTrip exercises the boundary's Ed25519 provenance
// helpers end to end: generate a key pair, sign a message, and verify it against
// the PEM-wrapped public key — the exact path the plugin host's trust policy uses
// (SUPPLY-004, AN-3).
func TestEd25519SignVerifyRoundTrip(t *testing.T) {
	pubDER, sign, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}
	msg := []byte("the exact .wasm module bytes")
	sig := sign(msg)

	if err := VerifyEd25519(pubDER, msg, sig); err != nil {
		t.Fatalf("VerifyEd25519 of a valid signature: %v", err)
	}

	// PEM round-trips back to the same DER and still verifies.
	pemBytes := MarshalPublicKeyPEM(pubDER)
	gotDER, err := ParseEd25519PublicKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParseEd25519PublicKeyPEM: %v", err)
	}
	if err := VerifyEd25519(gotDER, msg, sig); err != nil {
		t.Fatalf("VerifyEd25519 after PEM round-trip: %v", err)
	}
}

// TestEd25519VerifyRejects covers the fail-closed paths: a tampered message, a
// wrong-length signature, and a non-Ed25519 / malformed key all return an error.
func TestEd25519VerifyRejects(t *testing.T) {
	pubDER, sign, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("payload")
	sig := sign(msg)

	if err := VerifyEd25519(pubDER, []byte("payloaX"), sig); err == nil {
		t.Error("VerifyEd25519 accepted a signature over a DIFFERENT message")
	}
	if err := VerifyEd25519(pubDER, msg, sig[:len(sig)-1]); err == nil {
		t.Error("VerifyEd25519 accepted a wrong-length signature")
	}
	if err := VerifyEd25519([]byte("not a key"), msg, sig); err == nil {
		t.Error("VerifyEd25519 accepted a malformed public key")
	}

	// A valid RSA PKIX key is not Ed25519 → rejected by VerifyEd25519, and
	// ParseEd25519PublicKeyPEM rejects its PEM too.
	_, rsaSignerCertDER, err := SignCMS([]byte("x")) // yields an RSA cert we can pull a key from
	if err != nil {
		t.Fatal(err)
	}
	rsaPubDER, err := PublicKeyDERFromCert(rsaSignerCertDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEd25519(rsaPubDER, msg, sig); err == nil {
		t.Error("VerifyEd25519 accepted an RSA public key")
	}
	if _, err := ParseEd25519PublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaPubDER})); err == nil {
		t.Error("ParseEd25519PublicKeyPEM accepted an RSA key")
	}
}
