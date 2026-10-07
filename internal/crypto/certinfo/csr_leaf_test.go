// SPDX-License-Identifier: BUSL-1.1

package certinfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestLeafMatchesCSRRejectsSwappedKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "web.apps.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	makeLeaf := func(signer *ecdsa.PrivateKey) []byte {
		t.Helper()
		template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "web.apps.test"},
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &signer.PublicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	matched, err := LeafMatchesCSR(csr, makeLeaf(key))
	if err != nil || !matched {
		t.Fatalf("matching leaf: matched=%v err=%v", matched, err)
	}
	matched, err = LeafMatchesCSR(csr, makeLeaf(other))
	if err != nil || matched {
		t.Fatalf("swapped key: matched=%v err=%v", matched, err)
	}
	corrupt := append([]byte(nil), csr...)
	corrupt[len(corrupt)-1] ^= 0xff
	if matched, err := LeafMatchesCSR(corrupt, makeLeaf(key)); err == nil || matched {
		t.Fatalf("tampered CSR: matched=%v err=%v", matched, err)
	}
}

// FuzzLeafMatchesCSR keeps arbitrary CSR and certificate bytes inside the
// public crypto boundary. A malformed or mismatched pair must fail closed.
func FuzzLeafMatchesCSR(f *testing.F) {
	f.Add([]byte("0\x00"), []byte("0\x00"))
	f.Fuzz(func(t *testing.T, csrDER, certificate []byte) {
		_, _ = LeafMatchesCSR(csrDER, certificate)
	})
}
