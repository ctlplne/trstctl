// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// Ed25519SelfSignedRootDERForTest builds an Ed25519 self-signed root the way an
// air-gapped tool would (the served signer does not hold Ed25519 CA keys), so
// the import path can be proven against one. Test-only export (AN-3 keeps the
// standard-library crypto imports inside this package).
func Ed25519SelfSignedRootDERForTest(t *testing.T, profile HierarchyCAProfile) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: profile.CommonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(profile.TTL - time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            profile.MaxPathLen,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
