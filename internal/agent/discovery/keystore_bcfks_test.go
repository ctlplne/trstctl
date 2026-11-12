// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// X2-L2: a directory walk reads .bcfks files; a Bouncy Castle FIPS keystore
// opened with Java's default store password reports its key entries with the
// store's secret key and trusted certificate counts.
func TestKeystoreSourceReadsBCFKSStoresX2L2(t *testing.T) {
	data, err := os.ReadFile("../../crypto/bcfks/testdata/x2l2-keytool.bcfks")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fips.bcfks")
	if err := os.WriteFile(path, data, 0o600); err != nil { // #nosec G703 -- the test writes its fixture into its own t.TempDir() (CWE-22)
		t.Fatal(err)
	}
	found, err := NewKeystoreSource(nil, dir).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("found %d findings; want web and api-ec: %+v", len(found), found)
	}
	for _, f := range found {
		alias := f.Metadata["keystore_alias"]
		if (alias != "web" && alias != "api-ec") || f.Location != path+"#"+alias || f.Format != "BCFKS" ||
			f.Metadata["keystore_secret_keys"] != "2" || f.Metadata["keystore_trusted_certificates"] != "1" ||
			f.Metadata["integrity_verified"] != "true" || f.Fingerprint == "" {
			t.Fatalf("finding = %+v", f)
		}
	}
}
