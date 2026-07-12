// SPDX-License-Identifier: MPL-2.0

package jks_test

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto/jks"
)

// FuzzDecode drives arbitrary bytes through the Java KeyStore decoder. A JKS
// blob is an operator-supplied file (migration import), so a hostile or
// truncated keystore must fail closed — never panic, and never hand back key
// or certificate material alongside a nil error (TEST-FUZZASSERT-001
// reject-forgery invariant: a decode that "fails" must not leak partial
// material).
func FuzzDecode(f *testing.F) {
	f.Add([]byte(""), "changeit", "alias")
	f.Add([]byte("not a jks"), "", "")
	f.Add([]byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02}, "password", "key") // JKS magic + version, then nothing

	f.Fuzz(func(t *testing.T, data []byte, password, alias string) {
		keyPEM, chainPEM, err := jks.Decode(data, password, alias)
		if err != nil {
			if keyPEM != nil || chainPEM != nil {
				t.Fatalf("Decode returned an error but also material (key=%d chain=%d bytes) — a failed decode must not leak partial secrets", len(keyPEM), len(chainPEM))
			}
			return
		}
		// A nil-error decode must have produced a certificate chain at least; a
		// "success" with nothing is a silent-failure bug.
		if len(chainPEM) == 0 {
			t.Fatal("Decode returned a nil error but no certificate chain")
		}
	})
}

// FuzzDecodeTrustedCertificates fuzzes the trust-store decode path (no private
// keys) with the same fail-closed contract.
func FuzzDecodeTrustedCertificates(f *testing.F) {
	f.Add([]byte(""), "changeit")
	f.Add([]byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02}, "password")

	f.Fuzz(func(t *testing.T, data []byte, password string) {
		certs, err := jks.DecodeTrustedCertificates(data, password)
		if err != nil {
			if certs != nil {
				t.Fatalf("DecodeTrustedCertificates returned an error but also %d entries — a failed decode must return no material", len(certs))
			}
			return
		}
		for alias, der := range certs {
			if len(der) == 0 {
				t.Fatalf("trusted certificate %q decoded to zero bytes", alias)
			}
		}
	})
}
