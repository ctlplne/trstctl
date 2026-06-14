package crypto_test

import (
	"testing"

	"trustctl.io/trustctl/internal/crypto"
)

// FuzzParseCMPRequest hardens the CMP PKIMessage parser (an untrusted-input parser per
// CLAUDE.md §6): no input may crash it; it must always return cleanly (a request or an
// error), never both, and never panic.
func FuzzParseCMPRequest(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	f.Add([]byte("not a CMP message"))

	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := crypto.ParseCMPRequest(data)
		if err == nil && req == nil {
			t.Fatal("ParseCMPRequest returned nil request and nil error")
		}
	})
}
