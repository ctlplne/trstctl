// SPDX-License-Identifier: BUSL-1.1

package clusterfuzz

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto/jks"
)

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

// FuzzJCEKSEntries drives arbitrary bytes through the JCEKS reader (X2-L2):
// a keystore found on a host is untrusted input, so the reader, including its
// walk over Java-serialized secret keys, must fail closed and never pair an
// error with entries or a verified store.
func FuzzJCEKSEntries(f *testing.F) {
	f.Add(append([]byte{0xCE, 0xCE, 0xCE, 0xCE, 0, 0, 0, 2, 0, 0, 0, 0}, make([]byte, 20)...), "changeit")
	f.Add(append([]byte{0xCE, 0xCE, 0xCE, 0xCE, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 3, 0, 1, 'k', 0, 0, 0, 0, 0, 0, 0, 0,
		0xAC, 0xED, 0x00, 0x05, 0x70}, make([]byte, 20)...), "")
	f.Add([]byte{0xCE, 0xCE, 0xCE, 0xCE}, "password")

	f.Fuzz(func(t *testing.T, data []byte, password string) {
		entries, verified, err := jks.JCEKSEntries(data, [][]byte{[]byte(password)})
		if err != nil {
			if entries != nil || verified {
				t.Fatalf("JCEKSEntries returned an error with %d entries (verified %v)", len(entries), verified)
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
