// SPDX-License-Identifier: BUSL-1.1

package cloudsecret

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// A172-L3: a stored private key's credential carries the SHA-256 of its
// public key, the same hash a certificate for that key has; other
// credentials and an encrypted key carry none.
func TestStoredPrivateKeyCarriesItsPublicKeyHashA172L3(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	pemKey, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(pemKey)
	const subjectName = "a172l3.test"
	certDER, err := crypto.SelfSignedCACert(key, subjectName, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(certDER)
	if err != nil {
		t.Fatal(err)
	}
	found, err := InspectSecret("hashicorp-vault", Secret{Name: "web-tls", Value: append([]byte("tls key:\n"), pemKey...)})
	if err != nil || len(found) != 1 || found[0].Credential == nil {
		t.Fatalf("found %+v, %v", found, err)
	}
	if c := found[0].Credential; c.Rule != "private_key_pem" || c.SPKISHA256 != info.SPKISHA256 || c.Fingerprint == "" {
		t.Fatalf("the stored key: rule %q, public key hash %q, want %q", c.Rule, c.SPKISHA256, info.SPKISHA256)
	}
	encrypted := []byte("-----BEGIN " + "ENCRYPTED PRIVATE KEY-----\nMIIBvTBXBgkqhkiG9w0BBQ0wSjApa172l3\n-----END " + "ENCRYPTED PRIVATE KEY-----\n")
	if found, err := InspectSecret("hashicorp-vault", Secret{Name: "locked", Value: encrypted}); err != nil || len(found) != 1 || found[0].Credential.SPKISHA256 != "" {
		t.Fatalf("an encrypted key: %+v, %v", found, err)
	}
	token := []byte("ghp_" + "a172l3a172l3a172l3a172l3a172l3a172l3a1")
	if found, err := InspectSecret("hashicorp-vault", Secret{Name: "gh", Value: token}); err != nil || len(found) != 1 || found[0].Credential.SPKISHA256 != "" {
		t.Fatalf("a token: %+v, %v", found, err)
	}
}
