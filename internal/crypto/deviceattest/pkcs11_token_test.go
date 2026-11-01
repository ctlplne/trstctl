// SPDX-License-Identifier: BUSL-1.1

package deviceattest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

type tokenFixture struct {
	rootPEM       []byte
	intermediate  []byte
	root          *x509.Certificate
	intermediateC *x509.Certificate
	intermediateK *ecdsa.PrivateKey
}

func newTokenFixture(t *testing.T) tokenFixture {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "A175 Stand-in PIV Root CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "A175 Stand-in PIV Attestation"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(interDER)
	return tokenFixture{rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), intermediate: interDER,
		root: root, intermediateC: inter, intermediateK: interKey}
}

// attest issues the token's attestation of a key, with YubiKey PIV
// serial and policy extensions.
func (f tokenFixture) attest(t *testing.T, key *ecdsa.PublicKey) []byte {
	t.Helper()
	serial, _ := asn1.Marshal(int64(17500175))
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "YubiKey PIV Attestation 9c"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidYubicoSerial, Value: serial}, {Id: oidYubicoPolicy, Value: []byte{3, 2}}}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.intermediateC, key, f.intermediateK)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func csrFor(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "edge-ca"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestPKCS11TokenAttestationVerifiesTheCSRKeyToAPinnedRoot(t *testing.T) {
	f := newTokenFixture(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := csrFor(t, key)
	chain := [][]byte{f.attest(t, &key.PublicKey), f.intermediate}
	got, err := VerifyPKCS11TokenAttestation(chain, [][]byte{f.rootPEM}, csr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got.RootSHA256 == "" || got.Serial != "17500175" || got.PINPolicy != "always" || got.TouchPolicy != "always" {
		t.Fatalf("attestation = %+v", got)
	}

	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, tc := range map[string]struct {
		chain [][]byte
		roots [][]byte
		csr   []byte
	}{
		"another key":          {[][]byte{f.attest(t, &other.PublicKey), f.intermediate}, [][]byte{f.rootPEM}, csr},
		"untrusted root":       {chain, [][]byte{newTokenFixture(t).rootPEM}, csr},
		"missing intermediate": {chain[:1], [][]byte{f.rootPEM}, csr},
		"no pinned root":       {chain, nil, csr},
		"empty chain":          {nil, [][]byte{f.rootPEM}, csr},
	} {
		if _, err := VerifyPKCS11TokenAttestation(tc.chain, tc.roots, tc.csr, time.Now()); !errors.Is(err, ErrTokenAttestationRefused) {
			t.Fatalf("%s = %v, want refused", name, err)
		}
	}
	if _, err := VerifyPKCS11TokenAttestation(chain, [][]byte{f.rootPEM}, csr, time.Now().Add(48*time.Hour)); !errors.Is(err, ErrTokenAttestationRefused) {
		t.Fatalf("expired chain = %v, want refused", err)
	}
}
