// SPDX-License-Identifier: BUSL-1.1

package clusterfuzz

import (
	"crypto/x509"
	"encoding/asn1"
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
	f.Add(x2l8HostileMAC(f), "x2l8")

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

// x2l8HostileMAC is a minimal PKCS #12 file whose MAC asks for 2^31-1
// key-derivation iterations (X2-L8). The reader refuses it before any
// hashing; without that bound this seed alone keeps the fuzzer hashing.
func x2l8HostileMAC(f *testing.F) []byte {
	type algorithmIdentifier struct{ Algorithm asn1.ObjectIdentifier }
	type digestInfo struct {
		Algorithm algorithmIdentifier
		Digest    []byte
	}
	type macData struct {
		Mac        digestInfo
		MacSalt    []byte
		Iterations int
	}
	type contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit"`
	}
	type pfxPDU struct {
		Version  int
		AuthSafe contentInfo
		MacData  macData
	}
	marshal := func(v any) []byte {
		out, err := asn1.Marshal(v)
		if err != nil {
			f.Fatal(err)
		}
		return out
	}
	authSafe := marshal(marshal([]contentInfo{})) // an OCTET STRING holding an empty authenticated safe
	wrapped := marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: authSafe})
	return marshal(pfxPDU{
		Version:  3,
		AuthSafe: contentInfo{ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}, Content: asn1.RawValue{FullBytes: wrapped}},
		MacData: macData{
			Mac:        digestInfo{Algorithm: algorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}}, Digest: make([]byte, 20)},
			MacSalt:    make([]byte, 8),
			Iterations: 1<<31 - 1,
		},
	})
}
