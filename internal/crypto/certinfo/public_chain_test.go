// SPDX-License-Identifier: MPL-2.0

package certinfo

import (
	"bytes"
	"encoding/pem"
	"testing"
	"testing/quick"
)

func TestParsePublicPEMChainRejectsHiddenMaterialAndWrongLeaf(t *testing.T) {
	public, der := testCert(t)
	chain, err := ParsePublicPEMChain(public, der)
	if err != nil || !bytes.Equal(chain, public) {
		t.Fatalf("public chain = %q, %v", chain, err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("synthetic negative, not a key")})
	for name, raw := range map[string][]byte{
		"private prefix":           append(bytes.Clone(private), public...),
		"private suffix":           append(bytes.Clone(public), private...),
		"text prefix":              append([]byte("hidden\n"), public...),
		"malformed skipped prefix": append([]byte("-----BEGIN CERTIFICATE-----\nbad\n"), public...),
		"text suffix":              append(bytes.Clone(public), []byte("hidden")...),
		"oversize":                 bytes.Repeat([]byte("x"), MaxPublicChainBytes+1),
		"too many certificates":    bytes.Repeat(public, 9),
		"empty":                    nil,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePublicPEMChain(raw, der); err == nil {
				t.Fatal("accepted non-public or incomplete envelope")
			}
		})
	}
	if _, err := ParsePublicPEMChain(public, []byte("different DER")); err == nil {
		t.Fatal("accepted the wrong leaf")
	}
}

func TestParsePublicPEMChainPreservesExactCertificateOrder(t *testing.T) {
	first, der := testCert(t)
	second, _ := testCert(t)
	want := append(bytes.Clone(first), second...)
	got, err := ParsePublicPEMChain(want, der)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("public chain order changed: %v", err)
	}
}

func TestPropertyParsePublicPEMChainCannotHideAppendedBytes(t *testing.T) {
	public, der := testCert(t)
	property := func(extra []byte) bool {
		// A non-whitespace sentinel makes the entire suffix invalid even if the
		// random bytes themselves are empty or resemble another PEM prefix.
		raw := append(append(bytes.Clone(public), []byte("not-a-certificate\n")...), extra...)
		_, err := ParsePublicPEMChain(raw, der)
		return err != nil
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 100}); err != nil {
		t.Fatal(err)
	}
}

func FuzzParsePublicPEMChain(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n"), []byte("abc"))
	f.Fuzz(func(t *testing.T, raw, der []byte) {
		out, err := ParsePublicPEMChain(raw, der)
		if err == nil {
			if len(out) == 0 || len(out) > MaxPublicChainBytes {
				t.Fatal("unbounded successful result")
			}
			leaf, leafErr := LeafDER(out)
			if leafErr != nil || !bytes.Equal(leaf, der) {
				t.Fatal("successful result changed leaf identity")
			}
		}
	})
}
