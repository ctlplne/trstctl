// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

// FuzzInspectCSR drives arbitrary bytes through InspectCSR (csr.go), the single
// CSR-inspection seam used by certificate-profile validation, and through the EKU
// ASN.1 decode it calls (eku.go extKeyUsageNamesFromExtensions →
// extKeyUsageNamesFromDER). Profile validation runs InspectCSR on every
// attacker-supplied CSR (ACME finalize, EST/SCEP enroll, agent enrollment), and a
// CSR may carry an arbitrary extensionRequest whose ExtKeyUsage extension value is
// attacker-controlled ASN.1. A malformed CSR, or a valid CSR with a malformed/
// adversarial EKU extension, must fail closed (an error), never panic. TEST-FUZZASSERT-001.
//
// FUZZ-002: certinfo.Inspect was fuzzed (FuzzInspect) but crypto.InspectCSR — a
// different parser with its own EKU extension decode — was not directly fuzzed.
//
// This is an in-package (package crypto) test, so it may use crypto/x509 to mint
// valid and adversarial seeds — exactly as the boundary itself does (AN-3).
func FuzzInspectCSR(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err == nil {
		// (1) A valid CSR carrying a well-formed ExtKeyUsage extension (serverAuth +
		// clientAuth) reaches the success path through the EKU decode.
		ekuOIDs := []asn1.ObjectIdentifier{
			{1, 3, 6, 1, 5, 5, 7, 3, 1},
			{1, 3, 6, 1, 5, 5, 7, 3, 2},
		}
		if ekuVal, err := asn1.Marshal(ekuOIDs); err == nil {
			tmpl := &x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: "seed"},
				DNSNames: []string{"seed.example.com"},
				ExtraExtensions: []pkix.Extension{
					{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: ekuVal},
				},
			}
			if der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key); err == nil {
				f.Add(der)
			}
		}
		// (2) A valid, self-signed CSR carrying a MALFORMED ExtKeyUsage extension
		// value (truncated SEQUENCE) — the CSR parses, but the EKU ASN.1 decode must
		// reject the garbage rather than panic.
		tmplBad := &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "seed-bad-eku"},
			ExtraExtensions: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: []byte{0x30, 0x05, 0x06, 0x03, 0x2a}},
			},
		}
		if der, err := x509.CreateCertificateRequest(rand.Reader, tmplBad, key); err == nil {
			f.Add(der)
		}
	}
	f.Add([]byte(""))
	f.Add([]byte("not a csr"))
	f.Add([]byte{0x30, 0x80})       // indefinite-length DER preamble, no body
	f.Add([]byte{0x30, 0x84})       // long-form length, truncated
	f.Add([]byte{0x30, 0x05, 0x06}) // SEQUENCE claiming 5 bytes, truncated

	f.Fuzz(func(t *testing.T, der []byte) {
		// InspectCSR must never panic on hostile input; a malformed CSR or a bad EKU
		// extension legitimately returns an error.
		_, _ = InspectCSR(der)

		// Also drive the raw bytes straight through the EKU extension ASN.1 decoder
		// so the fuzzer can explore that parser directly (not only the subset of
		// bytes that survive full CSR parsing first). It too must never panic.
		_, _ = extKeyUsageNamesFromDER(der)
	})
}
