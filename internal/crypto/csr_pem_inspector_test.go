// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"encoding/pem"
	"errors"
	"testing"
)

func TestPublicCSRInspectorCannotBypassEnvelopeOrExposePartialFailure(t *testing.T) {
	valid, der := publicCSRPEMFixture(t)
	for name, raw := range map[string][]byte{
		"oversize": bytes.Repeat([]byte("x"), 65537),
		"prefix":   append([]byte("junk\n"), valid...),
		"two":      append(bytes.Clone(valid), valid...),
		"nested":   append([]byte("-----BEGIN CERTIFICATE REQUEST-----\n"), valid...),
		"headers":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Headers: map[string]string{"Comment": "header"}, Bytes: der}),
		"tail":     append(bytes.Clone(valid), []byte("junk")...),
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			got, info, err := ParsePublicCSRPEMWithInspector(raw, func([]byte) (CSRInfo, error) {
				called = true
				return CSRInfo{CommonName: "untrusted"}, nil
			})
			if err == nil || called || got != nil || info.CommonName != "" {
				t.Fatal("invalid envelope reached the algorithm verifier or exposed data")
			}
		})
	}
	if got, _, err := ParsePublicCSRPEMWithInspector(valid, nil); err == nil || got != nil {
		t.Fatal("nil proof verifier accepted")
	}
	want := errors.New("proof failed")
	got, info, err := ParsePublicCSRPEMWithInspector(valid, func(input []byte) (CSRInfo, error) {
		if !bytes.Equal(input, der) {
			t.Fatal("verifier received different DER")
		}
		return CSRInfo{CommonName: "partial"}, want
	})
	if !errors.Is(err, want) || got != nil || info.CommonName != "" {
		t.Fatal("verification failure exposed a partial result")
	}
}

func FuzzPublicCSRInspectorEnvelope(f *testing.F) {
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\nAQID\n-----END CERTIFICATE REQUEST-----\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\n-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		calls := 0
		der, _, err := ParsePublicCSRPEMWithInspector(raw, func([]byte) (CSRInfo, error) {
			calls++
			return CSRInfo{}, nil
		})
		if err != nil {
			if der != nil || calls != 0 {
				t.Fatal("invalid envelope reached verifier")
			}
			return
		}
		block, rest := pem.Decode(bytes.TrimSpace(raw))
		if calls != 1 || len(raw) > 65536 || block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 ||
			bytes.Count(raw, []byte("-----BEGIN ")) != 1 || bytes.Count(raw, []byte("-----END ")) != 1 || !bytes.Equal(block.Bytes, der) {
			t.Fatal("verifier accepted other than the exact bounded envelope")
		}
	})
}
