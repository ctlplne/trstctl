// SPDX-License-Identifier: MPL-2.0

package jose_test

import (
	"bytes"
	"testing"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// TestDigestSigningKeyUsesOpaqueSigner proves the JOSE wrapper can publish and
// verify RS256 while holding only a crypto-boundary DigestSigner. Production
// supplies a remote signer handle here, so the control plane never receives the
// audit/evidence private key (AUD-63 / AN-4).
func TestDigestSigningKeyUsesOpaqueSigner(t *testing.T) {
	signer, err := boundarycrypto.GenerateLockedKey(boundarycrypto.RSA2048)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}
	t.Cleanup(signer.Destroy)

	key, err := jose.NewDigestSigningKey("audit-export", signer)
	if err != nil {
		t.Fatalf("NewDigestSigningKey: %v", err)
	}
	payload := []byte(`{"kind":"audit-export","sequence":42}`)
	token, err := key.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := key.JWKS().Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	if _, err := key.MarshalPrivateKey(); err == nil {
		t.Fatal("opaque digest signing key exported private material")
	}
}

func TestDigestSigningKeyRejectsNonRSA(t *testing.T) {
	signer, err := boundarycrypto.GenerateLockedKey(boundarycrypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}
	t.Cleanup(signer.Destroy)
	if _, err := jose.NewDigestSigningKey("audit-export", signer); err == nil {
		t.Fatal("NewDigestSigningKey accepted ECDSA for RS256")
	}
}
