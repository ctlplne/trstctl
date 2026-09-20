// SPDX-License-Identifier: BUSL-1.1

// Package edgetest builds adversarial X.509 fixtures for B6 edge sub-CA
// tests. It lives below internal/crypto for the same reason deviceattesttest
// does: fixture certificate construction must not teach production packages
// to bypass the AN-3 crypto boundary. Everything here is an ATTACKER SHAPE —
// a leaf from a CA the brain never delegated, and a leaf the delegated key
// signed outside its constraints — so the tests that prove the brain catches
// them do not themselves need crypto/x509.
package edgetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// ForeignLeaf builds a leaf under a fresh, unrelated CA — the shape of a
// certificate somebody reports into a delegation's ledger that the delegated
// CA never issued.
func ForeignLeaf(cn string) (string, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "edgetest foreign root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return "", err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return "", err
	}
	return signLeaf(caCert, caKey, cn)
}

// RogueLeaf signs an arbitrary-name leaf with the DELEGATED key directly —
// the shape of a compromised host bypassing the agent's local constraint
// check. The certificate is real and chains to the delegation; only the
// brain's reconcile verdict can catch it.
func RogueLeaf(delegationCertPEM, delegationKeyPEM []byte, cn string) (string, error) {
	block, _ := pem.Decode(delegationCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("edgetest: no delegation certificate block")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	keyBlock, _ := pem.Decode(delegationKeyPEM)
	if keyBlock == nil {
		return "", fmt.Errorf("edgetest: no delegation key block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return "", err
	}
	caKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("edgetest: delegation key is not ECDSA")
	}
	return signLeaf(caCert, caKey, cn)
}

func signLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string) (string, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		return "", err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}
