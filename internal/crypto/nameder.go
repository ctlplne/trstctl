// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
