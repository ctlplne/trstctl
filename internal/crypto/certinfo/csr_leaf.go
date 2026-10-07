// SPDX-License-Identifier: BUSL-1.1

package certinfo

import (
	"bytes"
	"crypto/x509"
	"fmt"
)

// LeafMatchesCSR verifies the CSR's proof of possession and compares its exact
// public key to the first certificate in a DER or PEM chain. It does not grant
// trust to the certificate's issuer or claim that a workload serves it.
func LeafMatchesCSR(csrDER, certificate []byte) (bool, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return false, fmt.Errorf("certinfo: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return false, fmt.Errorf("certinfo: verify CSR signature: %w", err)
	}
	leafDER, err := LeafDER(certificate)
	if err != nil {
		return false, err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return false, err
	}
	return bytes.Equal(csr.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo), nil
}
