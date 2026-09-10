// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"bytes"
	"encoding/pem"
	"testing"
	"testing/quick"
)

func publicCSRPEMFixture(t testing.TB) ([]byte, []byte) {
	t.Helper()
	key, err := GenerateHostSubjectKey("exact.example.test", []string{"exact.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	der := bytes.Clone(key.CSRDER)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), der
}

func TestParsePublicCSRPEMRejectsSkippedOrAdditionalMaterial(t *testing.T) {
	valid, der := publicCSRPEMFixture(t)
	legacy := pem.EncodeToMemory(&pem.Block{Type: "NEW CERTIFICATE REQUEST", Bytes: der})
	for _, raw := range [][]byte{valid, legacy, append([]byte(" \n"), valid...), bytes.ReplaceAll(valid, []byte("\n"), []byte("\r\n"))} {
		got, info, err := ParsePublicCSRPEM(raw)
		if err != nil || !bytes.Equal(got, der) || info.CommonName != "exact.example.test" {
			t.Fatalf("valid single CSR refused or altered: %v", err)
		}
	}
	corrupt := bytes.Clone(der)
	corrupt[len(corrupt)-1] ^= 1
	for name, raw := range map[string][]byte{
		"empty":             nil,
		"oversize":          bytes.Repeat([]byte("x"), 65537),
		"arbitrary-prefix":  append([]byte("junk\n"), valid...),
		"two-valid":         append(bytes.Clone(valid), valid...),
		"mixed-labels":      append(bytes.Clone(legacy), valid...),
		"malformed-first":   append([]byte("-----BEGIN CERTIFICATE REQUEST-----\n!!!!\n-----END CERTIFICATE REQUEST-----\n"), valid...),
		"malformed-legacy":  append([]byte("-----BEGIN NEW CERTIFICATE REQUEST-----\n!!!!\n-----END NEW CERTIFICATE REQUEST-----\n"), valid...),
		"nested-begin":      append([]byte("-----BEGIN CERTIFICATE REQUEST-----\n"), valid...),
		"nested-mixed":      append([]byte("-----BEGIN NEW CERTIFICATE REQUEST-----\n"), valid...),
		"skipped-nonpublic": append([]byte("-----BEGIN CERTIFICATE REQUEST-----\n-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n"), valid...),
		"headers":           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Headers: map[string]string{"Comment": "header"}, Bytes: der}),
		"bad-signature":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: corrupt}),
		"trailing-junk":     append(bytes.Clone(valid), []byte("junk")...),
	} {
		t.Run(name, func(t *testing.T) {
			got, info, err := ParsePublicCSRPEM(raw)
			if err == nil || got != nil || info.CommonName != "" {
				t.Fatal("malformed CSR was accepted or exposed partial result")
			}
		})
	}
}

func TestPropertyPublicCSRPEMCannotHideTrailingBytes(t *testing.T) {
	valid, _ := publicCSRPEMFixture(t)
	property := func(tail []byte) bool {
		if len(bytes.TrimSpace(tail)) == 0 {
			return true
		}
		_, _, err := ParsePublicCSRPEM(append(bytes.Clone(valid), tail...))
		return err != nil
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 128}); err != nil {
		t.Fatal(err)
	}
}

func FuzzParsePublicCSRPEM(f *testing.F) {
	valid, _ := publicCSRPEMFixture(f)
	f.Add(valid)
	f.Add(append([]byte("-----BEGIN CERTIFICATE REQUEST-----\n"), valid...))
	f.Add(append([]byte("-----BEGIN NEW CERTIFICATE REQUEST-----\n!!!!\n-----END NEW CERTIFICATE REQUEST-----\n"), valid...))
	f.Fuzz(func(t *testing.T, raw []byte) {
		der, _, err := ParsePublicCSRPEM(raw)
		if err != nil {
			if der != nil {
				t.Fatal("rejected CSR returned partial DER")
			}
			return
		}
		block, rest := pem.Decode(bytes.TrimSpace(raw))
		if len(raw) > 65536 || block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 ||
			bytes.Count(raw, []byte("-----BEGIN ")) != 1 || bytes.Count(raw, []byte("-----END ")) != 1 || !bytes.Equal(block.Bytes, der) {
			t.Fatal("accepted CSR is not the exact single bounded envelope")
		}
		if _, err := InspectCSR(der); err != nil {
			t.Fatal("accepted CSR signature is invalid")
		}
	})
}
