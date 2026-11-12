// SPDX-License-Identifier: BUSL-1.1

package pfx

import (
	"crypto/x509"
	"errors"
	"os"
	"testing"
)

// x2l1JavaKeystore is a Java PKCS12 keystore made by keytool (OpenJDK
// 21.0.13, drafts/x2l1/make.sh) with its default store password: key
// entries tomcat (RSA-2048, signed by a lab CA, chain of 2), api-ec (EC
// P-256) and legacy (RSA-1024), and a trusted certificate entry
// partner-root. keytool writes three PBES2/AES-256 shrouded key bags and the
// five certificates, encrypted, with an HMAC-SHA256 MAC.
const x2l1JavaKeystore = "testdata/x2l1-java-multi-key.p12"

const x2l1StorePassword = "changeit" // #nosec G101 -- keytool's published default store password on a test fixture; not a credential (CWE-798)

// X2-L1: every key of a Java PKCS12 keystore is listed with its alias and
// chain, and the trusted entry is set apart, without decrypting any key.
func TestKeyEntriesReadsEveryKeyOfAJavaKeystoreX2L1(t *testing.T) {
	data, err := os.ReadFile(x2l1JavaKeystore)
	if err != nil {
		t.Fatal(err)
	}
	keys, trusted, err := KeyEntries(data, x2l1StorePassword)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		alias string
		chain []string
	}{
		{"tomcat", []string{"tomcat.x2l1.test", "X2-L1 Lab CA"}},
		{"api-ec", []string{"api.x2l1.test"}},
		{"legacy", []string{"legacy.x2l1.test"}},
	}
	if len(keys) != len(want) {
		t.Fatalf("KeyEntries listed %d keys; want %d", len(keys), len(want))
	}
	for i, w := range want {
		if keys[i].Alias != w.alias || len(keys[i].ChainDER) != len(w.chain) {
			t.Fatalf("key %d = alias %q with %d certificates; want %q with %d", i, keys[i].Alias, len(keys[i].ChainDER), w.alias, len(w.chain))
		}
		for j, der := range keys[i].ChainDER {
			cert, err := x509.ParseCertificate(der)
			if err != nil || cert.Subject.CommonName != w.chain[j] {
				t.Fatalf("%s chain[%d] = %v, %v; want CN=%s", w.alias, j, cert.Subject, err, w.chain[j])
			}
		}
	}
	if len(trusted) != 1 {
		t.Fatalf("trusted certificates = %d; want the partner-root entry alone", len(trusted))
	}
	if cert, err := x509.ParseCertificate(trusted[0]); err != nil || cert.Subject.CommonName != "X2-L1 Partner Root" {
		t.Fatalf("trusted entry = %v, %v", cert.Subject, err)
	}

	// The single-chain view callers already used still reads the file.
	chain, hasKey, err := ChainDER(data, x2l1StorePassword)
	if err != nil || !hasKey || len(chain) != 5 {
		t.Fatalf("ChainDER = %d certificates, key %v, %v; want all 5 and a key", len(chain), hasKey, err)
	}
	if _, _, err := KeyEntries(data, "not-the-store-password"); !errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("a wrong password: %v; want ErrIncorrectPassword", err)
	}
}
