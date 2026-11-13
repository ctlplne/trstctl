// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"encoding/pem"
	"testing"
	"time"
)

// A245-L3: the OCSP target of a stored chain is its leaf, the certificate in
// the chain that signed it (not merely the next one) and the leaf's responder
// URLs; a chain without the issuer names none.
func TestLeafOCSPTargetFindsTheSigningIssuerA245L3(t *testing.T) {
	caKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer caKey.Destroy()
	caDER, err := SelfSignedCACert(caKey, "A245-L3 Issuing CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer otherKey.Destroy()
	otherDER, err := SelfSignedCACert(otherKey, "A245-L3 Other CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer leafKey.Destroy()
	csr, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "a245l3.example.test"}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := SignLeafFromCSRWithProfile(caDER, caKey, csr, time.Hour, LeafProfile{OCSPServers: []string{"http://ocsp.a245l3.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	pemOf := func(ders ...[]byte) []byte {
		var out []byte
		for _, der := range ders {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		return out
	}
	leaf, issuer, urls, err := LeafOCSPTarget(pemOf(leafDER, otherDER, caDER))
	if err != nil || !bytes.Equal(leaf, leafDER) || !bytes.Equal(issuer, caDER) || len(urls) != 1 || urls[0] != "http://ocsp.a245l3.example.test" {
		t.Fatalf("target = leaf %v, issuer is CA %v, urls %v, %v", bytes.Equal(leaf, leafDER), bytes.Equal(issuer, caDER), urls, err)
	}
	if _, issuer, _, err := LeafOCSPTarget(pemOf(leafDER, otherDER)); err != nil || issuer != nil {
		t.Fatalf("a chain without the issuer named %v (%v)", issuer, err)
	}
	if _, _, _, err := LeafOCSPTarget([]byte("not pem")); err == nil {
		t.Fatal("a chain with no certificate was read")
	}
}
