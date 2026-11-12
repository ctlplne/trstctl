// SPDX-License-Identifier: BUSL-1.1

package certinfo

import (
	"bytes"
	"encoding/pem"
	"testing"
)

// TestCertificateChainDERKeepsTheReturnedOrder is B13-L1: a cloud provider's
// certificate and the chain returned after it come back as each certificate's
// DER, leaf first, from PEM, and a single DER certificate as itself.
func TestCertificateChainDERKeepsTheReturnedOrder(t *testing.T) {
	leafPEM, leafDER := testCert(t)
	issuerPEM, issuerDER := testCert(t)
	got, err := CertificateChainDER(append(append(bytes.Clone(leafPEM), '\n'), issuerPEM...))
	if err != nil || len(got) != 2 || !bytes.Equal(got[0], leafDER) || !bytes.Equal(got[1], issuerDER) {
		t.Fatalf("chain = %d certificates, %v; want the leaf then its issuer", len(got), err)
	}
	if got, err := CertificateChainDER(leafDER); err != nil || len(got) != 1 || !bytes.Equal(got[0], leafDER) {
		t.Fatalf("a DER certificate = %d certificates, %v", len(got), err)
	}
	eight := bytes.Repeat(issuerPEM, MaxChainCertificates-1)
	if got, err := CertificateChainDER(append(bytes.Clone(leafPEM), eight...)); err != nil || len(got) != MaxChainCertificates {
		t.Fatalf("a chain at the bound = %d certificates, %v", len(got), err)
	}
}

// TestCertificateChainDERRefusesAnythingButCertificates holds a returned chain
// to the public chain envelope: no other block, no text around or between the
// blocks, no headers, and no more than the bound.
func TestCertificateChainDERRefusesAnythingButCertificates(t *testing.T) {
	leafPEM, leafDER := testCert(t)
	issuerPEM, _ := testCert(t)
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("synthetic negative, not a key")})
	headed := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Note": "x"}, Bytes: leafDER})
	for name, raw := range map[string][]byte{
		"empty":                  nil,
		"oversize":               bytes.Repeat([]byte("x"), MaxPublicChainBytes+1),
		"a private key after":    append(bytes.Clone(leafPEM), private...),
		"a private key before":   append(bytes.Clone(private), leafPEM...),
		"text before":            append([]byte("hidden\n"), leafPEM...),
		"text between":           append(append(bytes.Clone(leafPEM), []byte("hidden\n")...), issuerPEM...),
		"text after":             append(bytes.Clone(leafPEM), []byte("hidden")...),
		"a malformed block":      append([]byte("-----BEGIN CERTIFICATE-----\nbad\n"), leafPEM...),
		"headers":                headed,
		"not a certificate":      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")}),
		"DER that is not a cert": []byte("not DER"),
		"over the bound":         append(bytes.Clone(leafPEM), bytes.Repeat(issuerPEM, MaxChainCertificates)...),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := CertificateChainDER(raw); err == nil {
				t.Fatalf("accepted %d certificates from a bundle that is not only certificates", len(got))
			}
		})
	}
}

// FuzzCertificateChainDER drives arbitrary provider bytes through the chain
// parser B13-L1 keeps cloud certificates with: it fails closed, never panics,
// returns a bounded, non-empty chain, and a chain it returns parses back to
// itself.
func FuzzCertificateChainDER(f *testing.F) {
	leafPEM, leafDER := testCert(f)
	f.Add([]byte{})
	f.Add(leafDER)
	f.Add(leafPEM)
	f.Add(append(bytes.Clone(leafPEM), leafPEM...))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		ders, err := CertificateChainDER(raw)
		if err != nil {
			return
		}
		if len(ders) == 0 || len(ders) > MaxChainCertificates {
			t.Fatalf("unbounded chain: %d certificates", len(ders))
		}
		var again []byte
		for _, der := range ders {
			if len(der) == 0 {
				t.Fatal("an empty certificate in a returned chain")
			}
			again = append(again, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		back, err := CertificateChainDER(again)
		if err != nil || len(back) != len(ders) {
			t.Fatalf("a returned chain does not parse back: %d certificates, %v", len(back), err)
		}
		for i := range ders {
			if !bytes.Equal(back[i], ders[i]) {
				t.Fatalf("certificate %d changed on the way back", i)
			}
		}
	})
}
