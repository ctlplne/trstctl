// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// A241: the request signature an OCI client sends verifies under the key's
// public half; an EC key is refused.
func TestSignRSASHA256WithPEMKey(t *testing.T) {
	key, err := GenerateLockedKey(RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	der, err := key.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	message := []byte("(request-target): get /20180608/secrets\nhost: vaults.us-ashburn-1.oci.oraclecloud.com")
	signature, err := SignRSASHA256WithPEMKey(keyPEM, message)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKIXPublicKey(key.Public().DER)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(message)
	if err := rsa.VerifyPKCS1v15(parsed.(*rsa.PublicKey), crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	ec, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ec.Destroy()
	ecDER, err := ec.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignRSASHA256WithPEMKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}), message); err == nil {
		t.Fatal("an EC key signed an RSA-SHA256 request")
	}
}
