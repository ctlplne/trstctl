// SPDX-License-Identifier: BUSL-1.1

package samlsp

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func encryptionIdentity(t *testing.T, alg crypto.Algorithm) (certDER, keyPKCS8 []byte) {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	certDER, err = crypto.SelfSignedCACert(signer, "samlsp encryption test", 3600e9)
	if err != nil {
		t.Fatal(err)
	}
	keyPKCS8, err = signer.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	return certDER, keyPKCS8
}

// A77: an SP given an RSA encryption identity advertises it in its metadata
// with use="encryption" and reports that it decrypts; a non-RSA key, a lone
// half, or a mismatched pair is refused at construction.
func TestEncryptionIdentityIsAdvertisedAndValidated(t *testing.T) {
	metadata := artifactIdPMetadata(t, false)
	certDER, keyPKCS8 := encryptionIdentity(t, crypto.RSA2048)
	cfg := artifactConfig(metadata)
	cfg.ResponseBinding = ""
	cfg.EncryptionCertDER, cfg.EncryptionKeyPKCS8 = certDER, keyPKCS8
	sp, err := NewServiceProvider(cfg)
	if err != nil || !sp.DecryptsAssertions() {
		t.Fatalf("SP with an RSA encryption identity = %v %v", sp, err)
	}
	spMetadata, err := sp.MetadataXML()
	if err != nil || !strings.Contains(string(spMetadata), `use="encryption"`) {
		t.Fatalf("SP metadata without an encryption KeyDescriptor: %v %s", err, spMetadata)
	}

	plain := artifactConfig(metadata)
	plain.ResponseBinding = ""
	if sp, err := NewServiceProvider(plain); err != nil || sp.DecryptsAssertions() {
		t.Fatalf("SP without an identity = %v %v, want plaintext only", sp, err)
	}
	half := plain
	half.EncryptionCertDER = certDER
	if _, err := NewServiceProvider(half); err == nil || !strings.Contains(err.Error(), "both the certificate and the key") {
		t.Fatalf("certificate without a key = %v", err)
	}
	ecCert, ecKey := encryptionIdentity(t, crypto.ECDSAP256)
	ec := plain
	ec.EncryptionCertDER, ec.EncryptionKeyPKCS8 = ecCert, ecKey
	if _, err := NewServiceProvider(ec); err == nil || !strings.Contains(err.Error(), "needs an RSA key") {
		t.Fatalf("ECDSA encryption identity = %v, want an RSA refusal", err)
	}
	otherCert, _ := encryptionIdentity(t, crypto.RSA2048)
	mismatched := plain
	mismatched.EncryptionCertDER, mismatched.EncryptionKeyPKCS8 = otherCert, keyPKCS8
	if _, err := NewServiceProvider(mismatched); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched pair = %v", err)
	}
}
