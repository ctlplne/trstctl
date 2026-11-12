// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"os"
	"testing"
)

// X2-L2: a JCEKS keystore made by keytool reports its two key entries with
// type and size, its trusted certificate and its two secret keys, verified
// with Java's default store password.
func TestInspectKeystoreReadsAJCEKSStoreX2L2(t *testing.T) {
	data, err := os.ReadFile("jks/testdata/x2l2-keytool.jceks")
	if err != nil {
		t.Fatal(err)
	}
	report, err := InspectKeystore(data, [][]byte{[]byte("changeit")})
	if err != nil {
		t.Fatal(err)
	}
	if report.Format != "JCEKS" || !report.IntegrityVerified || report.TrustedCerts != 1 || report.SecretKeys != 2 || len(report.Keys) != 2 {
		t.Fatalf("report = %+v; want JCEKS, verified, 2 keys, 1 trusted, 2 secret keys", report)
	}
	for _, key := range report.Keys {
		switch key.Alias {
		case "web":
			if key.KeyType != "RSA" || key.KeyBits != 2048 || key.ChainLength != 1 {
				t.Fatalf("web = %+v", key)
			}
		case "api-ec":
			if key.KeyType != "ECDSA" || key.KeyBits != 256 || key.ChainLength != 1 {
				t.Fatalf("api-ec = %+v", key)
			}
		default:
			t.Fatalf("unexpected key %q", key.Alias)
		}
	}
}
