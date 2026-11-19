// SPDX-License-Identifier: BUSL-1.1

package certinfo

import (
	"bytes"
	"encoding/pem"
	"os"
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

// CR-431. Public trust bundles use the same exact PEM envelope as chains,
// with an independent size bound and no leaf-identity requirement.
func TestNormalizePublicCertificatePEM(t *testing.T) {
	first, der := testCert(t)
	second, _ := testCert(t)
	want := append(bytes.Clone(first), second...)
	raw := append(bytes.ReplaceAll(first, []byte("\n"), []byte("\r\n")), []byte("\n\n")...)
	raw = append(raw, second...)
	if got, err := NormalizePublicCertificatePEM(raw); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("normalization did not keep both certificates in order: %v", err)
	}
	header := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der, Headers: map[string]string{"Comment": "fixture"}})
	for name, raw := range map[string][]byte{
		"oversize":        bytes.Repeat([]byte(" "), MaxPublicCertificatePEMBytes+1),
		"text":            append([]byte("fixture notes\n"), first...),
		"header":          header,
		"malformed block": append([]byte("-----BEGIN CERTIFICATE-----\nfixture\n"), first...),
		"empty":           nil,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NormalizePublicCertificatePEM(raw); err == nil {
				t.Error("expected an exact public certificate envelope")
			}
		})
	}
}

func FuzzNormalizePublicCertificatePEM(f *testing.F) {
	seed, err := os.ReadFile("testdata/der-whitespace/signature-09.pem")
	if err != nil {
		f.Fatal(err)
		return
	}
	f.Add(seed)
	f.Add([]byte("fixture public notes"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := NormalizePublicCertificatePEM(raw)
		if err != nil {
			return
		}
		if len(got) == 0 || len(got) > MaxPublicCertificatePEMBytes {
			t.Fatal("invalid successful output size")
		}
		again, err := NormalizePublicCertificatePEM(got)
		if err != nil || !bytes.Equal(again, got) {
			t.Fatalf("public PEM was not canonical: %v", err)
		}
	})
}
