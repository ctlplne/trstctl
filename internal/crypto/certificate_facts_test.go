// SPDX-License-Identifier: BUSL-1.1

package crypto_test

import (
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestCertificateFactsFromPEM(t *testing.T) {
	for _, tc := range []struct{ file, algorithm, serial, cn string }{
		{"vault-pki-a.pem", "ecdsa-p256", "a11", "CN=a.vault-pki.example"},
		{"vault-pki-b.pem", "rsa-2048", "b22", "CN=b.vault-pki.example"},
	} {
		pemText, err := os.ReadFile(filepath.Join("..", "reconcile", "testdata", tc.file))
		if err != nil {
			t.Fatal(err)
		}
		facts, err := crypto.CertificateFactsFromPEM(pemText)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if facts.Algorithm != tc.algorithm || facts.SerialHex != tc.serial || facts.SubjectDN != tc.cn || len(facts.IssuerNameDER) == 0 || !facts.NotAfter.After(facts.NotBefore) {
			t.Fatalf("%s: facts=%+v", tc.file, facts)
		}
	}
	if _, err := crypto.CertificateFactsFromPEM([]byte("not pem")); err == nil {
		t.Fatal("non-PEM input must fail")
	}
}
