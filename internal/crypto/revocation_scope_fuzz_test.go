// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"testing"
)

// ParseCRL receives untrusted distribution-point bytes. Keep a signed,
// scoped list in the seed set so mutations can reach the new IDP decoder.
func FuzzParseCRL(f *testing.F) {
	f.Fuzz(func(t *testing.T, crlDER, issuerDER []byte) {
		_, _ = ParseCRL(crlDER, issuerDER)
	})
}

// The signed IDP extension is also parsed directly so malformed nested
// GeneralNames reach the decoder without first needing a valid CA signature.
func FuzzParseIssuingDistributionPointURLs(f *testing.F) {
	f.Add([]byte{0x30, 0x07, 0xa0, 0x05, 0xa0, 0x03, 0x86, 0x01, 'a'})
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		uris, err := parseIssuingDistributionPointURLs(der)
		if err == nil && len(uris) == 0 {
			t.Fatal("IDP parser accepted an empty URI scope")
		}
	})
}
