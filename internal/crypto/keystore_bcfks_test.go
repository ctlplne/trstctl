// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

// X2-L2: a BCFKS store made by keytool with the Bouncy Castle provider reports
// its two key entries, its trusted certificate and its two secret keys once
// its password opens it; with no password that opens it, it is locked.
func TestInspectKeystoreReadsABCFKSStoreX2L2(t *testing.T) {
	data, err := os.ReadFile("bcfks/testdata/x2l2-keytool.bcfks")
	if err != nil {
		t.Fatal(err)
	}
	report, err := InspectKeystore(data, [][]byte{[]byte("wrong"), []byte("changeit")})
	if err != nil {
		t.Fatal(err)
	}
	if report.Format != "BCFKS" || !report.IntegrityVerified || report.TrustedCerts != 1 || report.SecretKeys != 2 || len(report.Keys) != 2 {
		t.Fatalf("report = %+v; want BCFKS, verified, 2 keys, 1 trusted, 2 secret keys", report)
	}
	want := map[string]string{"web": "RSA-2048", "api-ec": "ECDSA-256"}
	for _, key := range report.Keys {
		if got := fmt.Sprintf("%s-%d", key.KeyType, key.KeyBits); want[key.Alias] != got {
			t.Fatalf("key %q = %s; want %q", key.Alias, got, want[key.Alias])
		}
	}
	locked, err := InspectKeystore(data, [][]byte{[]byte("wrong")})
	if !errors.Is(err, ErrKeystoreLocked) || locked.Format != "BCFKS" {
		t.Fatalf("with a wrong password = %+v, %v; want a locked BCFKS store", locked, err)
	}
}
