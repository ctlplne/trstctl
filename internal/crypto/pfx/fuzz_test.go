// SPDX-License-Identifier: MPL-2.0

package pfx_test

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto/pfx"
)

// FuzzDecode drives arbitrary bytes through the PKCS#12 (.pfx/.p12) decoder. A
// PFX blob is an operator-supplied import file, so a hostile or truncated
// container must fail closed — never panic, and never return key or chain
// material with a nil error only to pair it with a decode failure
// (TEST-FUZZASSERT-001 reject-forgery invariant).
func FuzzDecode(f *testing.F) {
	f.Add([]byte(""), "changeit")
	f.Add([]byte("not a pfx"), "")
	f.Add([]byte{0x30, 0x82, 0x00, 0x00}, "password") // ASN.1 SEQUENCE header, truncated

	f.Fuzz(func(t *testing.T, data []byte, password string) {
		keyPEM, chainPEM, err := pfx.Decode(data, password)
		if err != nil {
			if keyPEM != nil || chainPEM != nil {
				t.Fatalf("Decode returned an error but also material (key=%d chain=%d bytes) — a failed PFX decode must not leak partial secrets", len(keyPEM), len(chainPEM))
			}
			return
		}
		if len(chainPEM) == 0 && len(keyPEM) == 0 {
			t.Fatal("Decode returned a nil error but neither a key nor a chain")
		}
	})
}
