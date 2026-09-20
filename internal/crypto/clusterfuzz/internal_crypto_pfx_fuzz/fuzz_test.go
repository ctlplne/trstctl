// SPDX-License-Identifier: BUSL-1.1

package clusterfuzz

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto/pfx"
)

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
