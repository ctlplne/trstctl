// SPDX-License-Identifier: BUSL-1.1

// Package certtest builds bulk X.509 fixtures for scale tests, and a private
// CA with a server certificate for TLS tests. It lives below
// internal/crypto for the same reason edgetest does: fixture certificate
// construction must not teach test packages elsewhere to bypass the AN-3
// crypto boundary. Every key is generated for the fixture and discarded; the
// certificates are never trusted for anything.
package certtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// TLSLeaf returns a self-signed TLS server certificate for commonName, valid
// from notBefore to notAfter, asserting the given certificate policy OIDs in
// dotted form — a CA/Browser Forum reserved identifier makes it read as
// publicly trusted.
func TLSLeaf(commonName string, notBefore, notAfter time.Time, policyOIDs ...string) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	policies := make([]x509.OID, 0, len(policyOIDs))
	for _, dotted := range policyOIDs {
		oid, err := x509.ParseOID(dotted)
		if err != nil {
			return nil, err
		}
		policies = append(policies, oid)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial.Add(serial, big.NewInt(1)),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Policies:     policies,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
}

// DistinctLeaves returns n self-signed certificates, each over its own fresh
// P-256 key, so each carries a distinct SubjectPublicKeyInfo.
func DistinctLeaves(n int, commonNamePrefix string) ([][]byte, error) {
	out := make([][]byte, 0, n)
	notBefore := time.Now().Add(-time.Hour)
	for i := 0; i < n; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i) + 1),
			Subject:      pkix.Name{CommonName: fmt.Sprintf("%s-%d", commonNamePrefix, i)},
			NotBefore:    notBefore,
			NotAfter:     notBefore.Add(48 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			return nil, err
		}
		out = append(out, der)
	}
	return out, nil
}

// PrivateCAServer returns a private CA's certificate and a TLS server
// certificate it issued for names (DNS names or IP addresses), with that
// server's PKCS #8 key, all PEM: a server whose CA no system trusts. Both are
// valid for a day.
func PrivateCAServer(names ...string) (caPEM, certPEM, keyPEM []byte, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	notBefore := time.Now().Add(-time.Hour)
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "trstctl test private CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(25 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(25 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			leaf.IPAddresses = append(leaf.IPAddresses, ip)
		} else {
			leaf.DNSNames = append(leaf.DNSNames, name)
		}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), nil
}
