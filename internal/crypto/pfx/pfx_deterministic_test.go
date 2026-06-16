package pfx_test

import (
	"bytes"
	"encoding/pem"
	"testing"

	"trstctl.com/trstctl/internal/crypto/pfx"
)

// derOf decodes the first PEM block and returns its DER bytes, so two PEM
// encodings of the same object compare equal regardless of formatting.
func derOf(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no PEM block")
	}
	return block.Bytes
}

// EncodeDeterministic is a pure function of its input: the same credential and
// password always encode to byte-identical PKCS#12, which is what makes a
// keystore deployment idempotent.
func TestEncodeDeterministicIsStable(t *testing.T) {
	certPEM, keyPEM := credential(t)

	a, err := pfx.EncodeDeterministic(keyPEM, certPEM, "changeit")
	if err != nil {
		t.Fatal(err)
	}
	b, err := pfx.EncodeDeterministic(keyPEM, certPEM, "changeit")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("EncodeDeterministic must produce identical bytes for identical input")
	}

	// A different password changes the output (the salt is derived from it).
	c, err := pfx.EncodeDeterministic(keyPEM, certPEM, "other")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, c) {
		t.Error("a different password must change the encoded keystore")
	}
}

// A deterministically-encoded keystore decodes back to the original key and
// certificate, and only with the correct password.
func TestEncodeDeterministicRoundTrips(t *testing.T) {
	certPEM, keyPEM := credential(t)

	blob, err := pfx.EncodeDeterministic(keyPEM, certPEM, "changeit")
	if err != nil {
		t.Fatal(err)
	}
	gotKey, gotCert, err := pfx.Decode(blob, "changeit")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(derOf(t, gotKey), derOf(t, keyPEM)) {
		t.Error("round-tripped key DER mismatch")
	}
	if !bytes.Equal(derOf(t, gotCert), derOf(t, certPEM)) {
		t.Error("round-tripped leaf certificate DER mismatch")
	}
	if _, _, err := pfx.Decode(blob, "wrong"); err == nil {
		t.Error("decode with the wrong password must fail")
	}
}
