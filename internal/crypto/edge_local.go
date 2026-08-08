// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Edge-host local operations (epic B6): the key/CSR the host generates before
// asking for a delegation, and the local leaf issuance it performs while it
// has no path to the brain. Both live inside the crypto boundary (AN-3) — the
// agent binary calls these, it never touches crypto/* itself.
//
// The delegated key here is SOFTWARE-BACKED, persisted as a PEM file the host
// operator protects. TPM/PKCS#11-backed storage for this key is not built;
// what the TPM does provide today is the ATTESTATION gate at mint time. The
// bound that holds either way is the certificate itself: name constraints,
// path length zero, and an expiry measured in days.

// GenerateEdgeCAKeyAndCSR creates the edge CA's keypair locally and a CSR over
// it. The private key never travels: only the CSR does, and the mint's proof
// of possession is the CSR's self-signature.
func GenerateEdgeCAKeyAndCSR(commonName string) (keyPEM, csrDER []byte, err error) {
	if strings.TrimSpace(commonName) == "" {
		return nil, nil, fmt.Errorf("crypto: edge CA CSR needs a common name")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: generate edge CA key: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: marshal edge CA key: %w", err)
	}
	defer secret.Wipe(keyDER)
	csrDER, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: strings.TrimSpace(commonName)},
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: create edge CA CSR: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return keyPEM, csrDER, nil
}

// EdgeLeafRequest is one local issuance on the edge host.
type EdgeLeafRequest struct {
	CommonName string
	DNSNames   []string
	TTL        time.Duration
}

// EdgeIssuedLeaf is the locally issued certificate and its key. The
// certificate is what the journal records for reconciliation; the KEY goes
// only to the workload's key file and never into the journal — the brain has
// no business holding it.
type EdgeIssuedLeaf struct {
	SerialHex      string
	CertificateDER []byte
	CertificatePEM []byte
	LeafKeyPEM     []byte
	NotAfter       time.Time
}

// IssueEdgeLeaf issues one leaf locally under a delegated edge CA. The
// CONSTRAINTS COME FROM THE CERTIFICATE — the permitted and excluded name
// subtrees and the CA's own expiry are read from the delegation itself, so a
// tampered local config cannot widen what the brain delegated. The same check
// the brain applies at reconciliation applies here first: an out-of-constraint
// request fails closed on the edge host, it does not become a certificate that
// gets flagged later.
func IssueEdgeLeaf(delegationCertPEM, delegationKeyPEM []byte, req EdgeLeafRequest, now time.Time) (EdgeIssuedLeaf, error) {
	block, _ := pem.Decode(delegationCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: delegated CA PEM has no certificate block")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: parse delegated CA certificate: %w", err)
	}
	keyBlock, _ := pem.Decode(delegationKeyPEM)
	if keyBlock == nil {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: delegated CA key PEM has no block")
	}
	defer secret.Wipe(keyBlock.Bytes)
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: parse delegated CA key: %w", err)
	}
	caKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: delegated CA key must be an ECDSA key")
	}

	constraints := EdgeConstraints{
		PermittedDNSDomains: append([]string(nil), caCert.PermittedDNSDomains...),
		ExcludedDNSDomains:  append([]string(nil), caCert.ExcludedDNSDomains...),
		NotAfter:            caCert.NotAfter,
	}
	names := req.DNSNames
	if len(names) == 0 && strings.TrimSpace(req.CommonName) != "" {
		names = []string{strings.TrimSpace(req.CommonName)}
	}
	if err := CheckEdgeIssuance(constraints, names, nil, now); err != nil {
		return EdgeIssuedLeaf{}, err
	}

	ttl := req.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	notAfter := EdgeLeafNotAfter(constraints, now.Add(ttl))
	serial, err := randomSerial()
	if err != nil {
		return EdgeIssuedLeaf{}, err
	}
	leafKeyless := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: strings.TrimSpace(req.CommonName)},
		DNSNames:     names,
		NotBefore:    IssuanceNotBefore(now),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	// The leaf's key is generated here too: the edge issues complete identity
	// material for the workload beside it.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: generate leaf key: %w", err)
	}
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: marshal leaf key: %w", err)
	}
	defer secret.Wipe(leafKeyDER)
	der, err := x509.CreateCertificate(rand.Reader, leafKeyless, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: sign edge leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return EdgeIssuedLeaf{}, err
	}
	return EdgeIssuedLeaf{
		SerialHex:      leaf.SerialNumber.Text(16),
		CertificateDER: der,
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		LeafKeyPEM:     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER}),
		NotAfter:       leaf.NotAfter,
	}, nil
}
