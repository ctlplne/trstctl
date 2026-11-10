// SPDX-License-Identifier: BUSL-1.1

package clusterfuzz

import (
	"crypto/x509"
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

// FuzzChainDER drives the certificate-only PKCS #12 reader (X2-L3) that
// inventory runs on files found on hosts: hostile bytes and any password must
// return an error or certificates, never panic, and a success is at least one
// parseable certificate.
func FuzzChainDER(f *testing.F) {
	f.Add([]byte(""), "")
	f.Add([]byte("not a pfx"), "changeit")
	f.Add([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, "password")
	f.Add([]byte{0x30, 0x0b, 0x02, 0x01, 0x03, 0x30, 0x06, 0x06, 0x01, 0x00, 0xa0, 0x01, 0x00}, "")

	f.Fuzz(func(t *testing.T, data []byte, password string) {
		chain, _, err := pfx.ChainDER(data, password)
		if err != nil {
			if len(chain) != 0 {
				t.Fatalf("ChainDER returned an error and %d certificates", len(chain))
			}
			return
		}
		if len(chain) == 0 {
			t.Fatal("ChainDER returned no error and no certificate")
		}
		for i, der := range chain {
			if _, perr := x509.ParseCertificate(der); perr != nil {
				t.Fatalf("certificate %d does not parse: %v", i, perr)
			}
		}
	})
}
