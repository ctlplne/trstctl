// SPDX-License-Identifier: BUSL-1.1

package clusterfuzz

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

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
