// SPDX-License-Identifier: BUSL-1.1

package certinfo

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

// Embedding keeps native and OSS-Fuzz seeds independent of the working directory.
//
//go:embed testdata/der-whitespace/*.pem
var whitespaceSignatureSeeds embed.FS

func whitespaceSignatureFixtures(t testing.TB) [][]byte {
	t.Helper()
	paths, err := whitespaceSignatureSeeds.ReadDir("testdata/der-whitespace")
	if err != nil || len(paths) != 6 {
		t.Fatalf("signed whitespace fixtures: count=%d err=%v", len(paths), err)
	}
	var fixtures [][]byte
	for _, entry := range paths {
		path := "testdata/der-whitespace/" + entry.Name()
		raw, err := whitespaceSignatureSeeds.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			t.Fatalf("invalid public fixture %s", path)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if err := cert.CheckSignatureFrom(cert); err != nil {
			t.Fatalf("fixture signature does not verify: %s: %v", path, err)
		}
		if len(bytes.TrimSpace(cert.Raw)) >= len(cert.Raw) {
			t.Fatalf("fixture does not reproduce binary truncation: %s", path)
		}
		fixtures = append(fixtures, bytes.Clone(cert.Raw))
	}
	return fixtures
}

func TestInspectAllPreservesWhitespaceSignatureBytes(t *testing.T) {
	for _, der := range whitespaceSignatureFixtures(t) {
		t.Run(hex.EncodeToString(der[len(der)-1:]), func(t *testing.T) {
			want, err := Inspect(der)
			if err != nil {
				t.Fatal(err)
			}
			before := bytes.Clone(der)
			infos, err := InspectAll(der)
			if err != nil || len(infos) != 1 {
				t.Fatalf("valid DER disappeared: count=%d err=%v", len(infos), err)
			}
			if infos[0].SHA256Fingerprint != want.SHA256Fingerprint || infos[0].SPKISHA256 != want.SPKISHA256 {
				t.Fatal("certificate identity changed")
			}
			if !bytes.Equal(before, der) {
				t.Fatal("parser mutated input")
			}
			expected, err := ExpectationFromChain(der)
			if err != nil || expected.SHA256Fingerprint != want.SHA256Fingerprint {
				t.Fatalf("verification lost valid DER identity: %+v %v", expected, err)
			}
		})
	}
}

func TestInspectAllKeepsTextEnvelopeWhitespaceSupport(t *testing.T) {
	for _, der := range whitespaceSignatureFixtures(t) {
		want, err := Inspect(der)
		if err != nil {
			t.Fatal(err)
		}
		envelopes := map[string][]byte{
			"pem":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			"base64": []byte(base64.StdEncoding.EncodeToString(der)),
		}
		for name, raw := range envelopes {
			t.Run(name+"-"+hex.EncodeToString(der[len(der)-1:]), func(t *testing.T) {
				padded := append([]byte(" \n\t"), raw...)
				padded = append(padded, []byte("\r\n\t ")...)
				infos, err := InspectAll(padded)
				if err != nil || len(infos) != 1 || infos[0].SHA256Fingerprint != want.SHA256Fingerprint {
					t.Fatalf("text envelope lost certificate: count=%d err=%v", len(infos), err)
				}
			})
		}
	}
}

func FuzzInspectAllPreservesValidDER(f *testing.F) {
	for _, der := range whitespaceSignatureFixtures(f) {
		f.Add(der)
	}
	f.Add([]byte("not a certificate"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		before := bytes.Clone(raw)
		infos, err := InspectAll(raw)
		if !bytes.Equal(raw, before) {
			t.Fatal("parser mutated input")
		}
		cert, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil {
			return
		}
		sum := sha256.Sum256(cert.Raw)
		if err != nil || len(infos) != 1 || infos[0].SHA256Fingerprint != hex.EncodeToString(sum[:]) {
			t.Fatalf("valid DER lost or changed: count=%d err=%v", len(infos), err)
		}
	})
}
