// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

// FuzzVerifyCertificateRequest drives arbitrary bytes through the boundary CSR
// parser (x509.ParseCertificateRequest + self-signature check). Every issuance
// path (ACME finalize, agent enrollment, EST/SCEP later) parses an untrusted CSR
// through this boundary, so it must fail closed on malformed input, never panic.
// TEST-FUZZASSERT-001.
//
// This is an in-package (package crypto) test, so it may use crypto/x509 to mint a
// valid seed — exactly as the boundary itself does (AN-3).
func FuzzVerifyCertificateRequest(f *testing.F) {
	if key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err == nil {
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject:  pkix.Name{CommonName: "seed"},
			DNSNames: []string{"seed.example.com"},
		}, key)
		if err == nil {
			f.Add(der) // a valid, self-signed CSR reaches the success path
		}
	}
	f.Add([]byte(""))
	f.Add([]byte("not a csr"))
	f.Add([]byte{0x30, 0x80}) // indefinite-length DER preamble, no body

	f.Fuzz(func(t *testing.T, der []byte) {
		_ = VerifyCertificateRequest(der) // must never panic
	})
}
