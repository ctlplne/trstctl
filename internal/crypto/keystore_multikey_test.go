// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"os"
	"testing"
)

// X2-L1: a Java PKCS12 keystore with several key aliases (made by keytool,
// internal/crypto/pfx/testdata) reports every key with its alias, type,
// size and chain, the weak one flagged, and its trusted entry counted.
func TestInspectKeystoreReadsEveryKeyOfAJavaPKCS12X2L1(t *testing.T) {
	data, err := os.ReadFile("pfx/testdata/x2l1-java-multi-key.p12")
	if err != nil {
		t.Fatal(err)
	}
	report, err := InspectKeystore(data, [][]byte{[]byte("wrong"), []byte("changeit")})
	if err != nil {
		t.Fatal(err)
	}
	if report.Format != "PKCS12" || !report.IntegrityVerified || report.TrustedCerts != 1 || len(report.Keys) != 3 {
		t.Fatalf("report = %d keys, %d trusted, format %s, verified %v; want 3 keys and 1 trusted PKCS12",
			len(report.Keys), report.TrustedCerts, report.Format, report.IntegrityVerified)
	}
	want := map[string]struct {
		keyType     string
		bits, chain int
		weak        bool
	}{
		"tomcat": {"RSA", 2048, 2, false},
		"api-ec": {"ECDSA", 256, 1, false},
		"legacy": {"RSA", 1024, 1, true},
	}
	for _, key := range report.Keys {
		w, ok := want[key.Alias]
		if !ok {
			t.Fatalf("unexpected key alias %q", key.Alias)
		}
		delete(want, key.Alias)
		if key.KeyType != w.keyType || key.KeyBits != w.bits || key.ChainLength != w.chain || (len(key.WeakReasons) > 0) != w.weak ||
			key.FingerprintBasis != "public-spki-sha256" || len(key.FingerprintSHA256) != 64 {
			t.Fatalf("%s = %+v; want %s-%d, chain %d, weak %v", key.Alias, key, w.keyType, w.bits, w.chain, w.weak)
		}
	}
	if len(want) != 0 {
		t.Fatalf("keys not reported: %v", want)
	}
}
