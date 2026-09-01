// SPDX-License-Identifier: MPL-2.0

package clusterfuzz

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

var scepCrasherFUZZ001 = []byte{0x30, 0x84}

func FuzzParseSCEPResponse(f *testing.F) {
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		f.Fatal(err)
	}
	defer signer.Destroy()
	certDER, err := crypto.SelfSignedCACert(signer, "fuzz recipient", time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	keyPKCS8, err := signer.PKCS8()
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte(nil))
	f.Add(scepCrasherFUZZ001)                   // the FUZZ-001 crasher
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00}) // minimal DER SEQUENCE
	f.Add([]byte{0x30, 0x84, 0x00, 0x00, 0x00}) // long-form length, truncated body
	f.Add([]byte("not der at all"))

	f.Fuzz(func(t *testing.T, reply []byte) {
		out, err := crypto.ParseSCEPResponse(reply, certDER, keyPKCS8)
		if err == nil && out == nil {
			t.Fatal("ParseSCEPResponse returned nil cert and nil error")
		}
	})
}

func FuzzVerifyCMSSignature(f *testing.F) {
	// A valid CMS + its signer cert (used as the trust root) so the corpus
	// includes a well-formed message, not only garbage.
	validP7, rootDER, err := crypto.SignCMS([]byte("instance-identity-document"))
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte(nil), rootDER)
	f.Add(scepCrasherFUZZ001, rootDER) // the FUZZ-001 crasher
	f.Add(validP7, rootDER)            // a well-formed CMS
	f.Add([]byte{0x30, 0x84}, []byte(nil))
	f.Add([]byte("garbage"), rootDER)

	f.Fuzz(func(t *testing.T, p7DER, root []byte) {
		var roots [][]byte
		if len(root) > 0 {
			roots = [][]byte{root}
		}
		// We only assert the absence of a panic; an error (or nil content with a
		// nil error on a validly-signed-but-untrusted doc) are both acceptable.
		_, _ = crypto.VerifyCMSSignature(p7DER, roots)
	})
}
