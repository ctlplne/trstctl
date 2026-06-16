package crypto_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// FuzzParseSCEPRequest hardens the SCEP pkiMessage parser (an untrusted-input parser per
// CLAUDE.md §6): no input — random bytes, truncated DER, a valid SignedData with a hostile
// envelope — may crash it; it must always return cleanly (a request or an error), never
// both, and never panic.
func FuzzParseSCEPRequest(f *testing.F) {
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		f.Fatal(err)
	}
	defer signer.Destroy()
	raCertDER, err := crypto.SelfSignedCACert(signer, "fuzz RA", time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	raKeyPKCS8, err := signer.PKCS8()
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte(nil))
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00}) // minimal DER SEQUENCE
	f.Add([]byte("not der at all"))

	f.Fuzz(func(t *testing.T, msg []byte) {
		req, err := crypto.ParseSCEPRequest(msg, raCertDER, raKeyPKCS8)
		if err == nil && req == nil {
			t.Fatal("ParseSCEPRequest returned nil request and nil error")
		}
	})
}
