// SPDX-License-Identifier: BUSL-1.1

package weakkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func selfSignedForSPKITest(t *testing.T, pub, priv any) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "spki test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// eMudhra, Part 4: the inventory carries an RSA key's public half for the
// control plane's blocklists and batch GCD; only RSA keys qualify.
func TestRSASubjectPublicKeyInfoKeepsOnlyRSAKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSignedForSPKITest(t, &rsaKey.PublicKey, rsaKey)
	spki, ok := RSASubjectPublicKeyInfo(cert.Raw)
	if !ok || !bytes.Equal(spki, cert.RawSubjectPublicKeyInfo) {
		t.Fatal("an RSA certificate's key was not its raw SubjectPublicKeyInfo")
	}
	if again, ok := RSASubjectPublicKeyInfo(spki); !ok || !bytes.Equal(again, spki) {
		t.Fatal("an RSA SubjectPublicKeyInfo did not round-trip")
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := RSASubjectPublicKeyInfo(selfSignedForSPKITest(t, &ecKey.PublicKey, ecKey).Raw); ok {
		t.Fatal("an ECDSA certificate gave an RSA key")
	}
	if _, ok := RSASubjectPublicKeyInfo([]byte("not der")); ok {
		t.Fatal("junk gave an RSA key")
	}
}
