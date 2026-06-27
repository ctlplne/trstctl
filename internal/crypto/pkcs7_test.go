package crypto_test

import (
	"bytes"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// makeCert builds a real self-signed CA cert DER for round-tripping.
func makeCert(t *testing.T, cn string) []byte {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	der, err := crypto.SelfSignedCACert(signer, cn, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestDegeneratePKCS7RoundTrip(t *testing.T) {
	a := makeCert(t, "ca-a")
	b := makeCert(t, "ca-b")

	p7, err := crypto.DegeneratePKCS7([][]byte{a, b})
	if err != nil {
		t.Fatalf("DegeneratePKCS7: %v", err)
	}
	got, err := crypto.CertsFromPKCS7(p7)
	if err != nil {
		t.Fatalf("CertsFromPKCS7: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d certs, want 2", len(got))
	}
	// Order preserved and the bytes match the input certificates exactly.
	for i, want := range [][]byte{a, b} {
		if string(got[i]) != string(want) {
			t.Errorf("cert %d bytes differ after round-trip", i)
		}
	}
}

func TestDegeneratePKCS7RejectsEmpty(t *testing.T) {
	if _, err := crypto.DegeneratePKCS7(nil); err == nil {
		t.Error("empty cert list should error")
	}
}

func TestCertsFromPKCS7RejectsGarbage(t *testing.T) {
	if _, err := crypto.CertsFromPKCS7([]byte{0x30, 0x00}); err == nil {
		t.Error("garbage PKCS#7 should fail closed")
	}
}

func TestEnvelopedDataBuildsCMSWithoutPlaintextResidue(t *testing.T) {
	recipient, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}
	t.Cleanup(recipient.Destroy)
	recipientDER, err := crypto.SelfSignedCACert(recipient, "est-serverkeygen-recipient", time.Hour)
	if err != nil {
		t.Fatalf("recipient cert: %v", err)
	}
	plaintext := []byte{
		'e', 's', 't', '-', 's', 'e', 'r', 'v', 'e', 'r', '-', 'g', 'e', 'n',
		'e', 'r', 'a', 't', 'e', 'd', '-', 'k', 'e', 'y',
	}

	enveloped, err := crypto.EnvelopedData(plaintext, recipientDER)
	if err != nil {
		t.Fatalf("EnvelopedData: %v", err)
	}
	if err := crypto.IsEnvelopedData(enveloped); err != nil {
		t.Fatalf("IsEnvelopedData: %v", err)
	}
	if bytes.Contains(enveloped, plaintext) {
		t.Fatal("CMS EnvelopedData contains plaintext key material")
	}
	if _, err := crypto.EnvelopedData(plaintext, nil); err == nil {
		t.Fatal("EnvelopedData with no recipient certificate succeeded")
	}
}
