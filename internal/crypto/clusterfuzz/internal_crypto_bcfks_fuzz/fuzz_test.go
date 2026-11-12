// SPDX-License-Identifier: BUSL-1.1

package clusterfuzz

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto/bcfks"
)

// FuzzBCFKSEntries drives arbitrary bytes through the BCFKS reader (X2-L2): a
// keystore found on a host is untrusted input, so the reader must fail closed
// and never pair an error with entries.
func FuzzBCFKSEntries(f *testing.F) {
	f.Add([]byte{0x30, 0x04, 0x30, 0x00, 0x30, 0x00}, "changeit")
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x03}, "")
	f.Add([]byte{0x30, 0x80}, "password")

	f.Fuzz(func(t *testing.T, data []byte, password string) {
		entries, err := bcfks.Entries(data, []byte(password))
		if err != nil {
			if entries != nil {
				t.Fatalf("Entries returned an error with %d entries", len(entries))
			}
			return
		}
		for _, e := range entries {
			if e.SecretKey && (e.KeyEntry || len(e.ChainDER) != 0) {
				t.Fatalf("secret key %q carries certificates or a key entry", e.Alias)
			}
		}
	})
}
