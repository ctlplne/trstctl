// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"testing"
	"testing/quick"
)

// CR-115: every simple DNS GeneralName remains usable, while a registeredID
// (which the external profile cannot authorize) is always refused.
func TestExternalProfileSANFormsPropertyCR115(t *testing.T) {
	property := func(letter uint8) bool {
		value := byte('a' + letter%26)
		dns := []byte{0x30, 0x03, 0x82, 0x01, value}
		registeredID := []byte{0x30, 0x03, 0x88, 0x01, value}
		return checkExternalProfileSANs(dns) == nil && checkExternalProfileSANs(registeredID) != nil
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 256}); err != nil {
		t.Fatal(err)
	}
}

// FuzzExternalProfileSANsCR115 is the untrusted ASN.1 boundary shared by
// external-CA CSR admission and returned-certificate validation.
func FuzzExternalProfileSANsCR115(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		{0x30, 0x03, 0x82, 0x01, 'a'},
		{0x30, 0x03, 0x88, 0x01, 'a'},
		{0x30, 0x02, 0xa0, 0x00},
		{0x30, 0x80},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, der []byte) {
		_ = checkExternalProfileSANs(der)
	})
}
