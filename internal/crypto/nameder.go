// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// Raw X.509 name readers for cross-authority identity derivation (C4/B6).
// Canonical certificate identity is (issuer Name DER, serial): the exact bytes
// two independent authorities can agree on without trusting each other's
// normalization. These helpers keep the parsing inside the AN-3 boundary so
// callers never touch crypto/x509 themselves.

// CertificateIssuerAndSerial parses a certificate (DER) and returns its issuer
// Name exactly as encoded, plus the serial in lowercase hex.
func CertificateIssuerAndSerial(der []byte) (issuerNameDER []byte, serialHex string, err error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", fmt.Errorf("crypto: parse certificate: %w", err)
	}
	return append([]byte(nil), cert.RawIssuer...), cert.SerialNumber.Text(16), nil
}

// CertificateSubjectNameDERFromPEM parses the FIRST certificate in a PEM
// bundle and returns its subject Name exactly as encoded — the issuer name
// every certificate it signs will carry.
func CertificateSubjectNameDERFromPEM(pemText []byte) ([]byte, error) {
	block, _ := pem.Decode(pemText)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("crypto: PEM bundle has no certificate block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse certificate: %w", err)
	}
	return append([]byte(nil), cert.RawSubject...), nil
}

// CertificateFacts is what a foreign authority's certificate asserts about
// itself, read inside the AN-3 boundary for cross-authority observation:
// identity (issuer Name DER + serial), key algorithm label, validity and the
// subject as a string. No key material, no extensions.
type CertificateFacts struct {
	IssuerNameDER []byte
	SerialHex     string
	Algorithm     string
	SubjectDN     string
	NotBefore     time.Time
	NotAfter      time.Time
}

// CertificateFactsFromPEM parses the first certificate block of pemText.
func CertificateFactsFromPEM(pemText []byte) (CertificateFacts, error) {
	block, _ := pem.Decode(pemText)
	if block == nil || block.Type != "CERTIFICATE" {
		return CertificateFacts{}, fmt.Errorf("crypto: PEM has no certificate block")
	}
	return CertificateFactsFromDER(block.Bytes)
}

// CertificateFactsFromDER parses one DER certificate.
func CertificateFactsFromDER(der []byte) (CertificateFacts, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return CertificateFacts{}, fmt.Errorf("crypto: parse certificate: %w", err)
	}
	return CertificateFacts{
		IssuerNameDER: append([]byte(nil), cert.RawIssuer...),
		SerialHex:     cert.SerialNumber.Text(16),
		Algorithm:     publicKeyAlgorithmLabel(cert),
		SubjectDN:     cert.Subject.String(),
		NotBefore:     cert.NotBefore.UTC(),
		NotAfter:      cert.NotAfter.UTC(),
	}, nil
}

func publicKeyAlgorithmLabel(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("rsa-%d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		if pub.Curve != nil && pub.Params() != nil {
			// "P-256" -> "ecdsa-p256", the label the rest of the platform uses.
			return "ecdsa-" + strings.ReplaceAll(strings.ToLower(pub.Params().Name), "-", "")
		}
		return "ecdsa"
	case ed25519.PublicKey:
		return "ed25519"
	}
	if pub, pure, err := purePublicKeyOfCertificate(cert); err == nil && pure {
		// "ML-DSA-65" -> "ml-dsa-65", the reviewed label of a post-quantum CA.
		return strings.ToLower(string(pub.Algorithm))
	}
	if label := strings.ToLower(cert.PublicKeyAlgorithm.String()); label != "" && label != "unknown" && label != "0" {
		return label
	}
	return "unknown"
}
