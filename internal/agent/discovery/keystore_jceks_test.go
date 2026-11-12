// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// X2-L2: a directory walk reads .jceks files. A keytool JCEKS store reports
// each key entry like a JKS one, with the store's secret keys counted; a
// store of secret keys only (a Hadoop credential store's shape) is reported
// once, as the keystore, with its secret key count.
func TestKeystoreSourceReadsJCEKSStoresX2L2(t *testing.T) {
	dir := t.TempDir()
	for name, fixture := range map[string]string{ // #nosec G101 -- fixture file paths, not credentials (CWE-798)
		"app.jceks":          "../../crypto/jks/testdata/x2l2-keytool.jceks",
		"hadoop/creds.jceks": "../../crypto/jks/testdata/x2l2-secrets-only.jceks",
	} {
		data, err := os.ReadFile(fixture) // #nosec G304 -- the test reads its own fixtures (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil { // #nosec G703 -- the test writes its fixture into its own t.TempDir() (CWE-22)
			t.Fatal(err)
		}
	}
	found, err := NewKeystoreSource(nil, dir).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byLocation := map[string]PrivateKeyFound{}
	for _, f := range found {
		byLocation[f.Location] = f
	}
	app := filepath.Join(dir, "app.jceks")
	creds := filepath.Join(dir, "hadoop/creds.jceks")
	if len(found) != 3 {
		t.Fatalf("found %d findings; want web, api-ec and the secret-only store: %+v", len(found), found)
	}
	for alias, want := range map[string][2]string{"web": {"RSA", "2048"}, "api-ec": {"ECDSA", "256"}} {
		f, ok := byLocation[app+"#"+alias]
		if !ok || f.Format != "JCEKS" || f.Metadata["key_type"] != want[0] || f.Metadata["key_size_bits"] != want[1] ||
			f.Metadata["keystore_secret_keys"] != "2" || f.Metadata["keystore_trusted_certificates"] != "1" ||
			f.Metadata["integrity_verified"] != "true" || f.Fingerprint == "" {
			t.Fatalf("%s = %+v", alias, f)
		}
	}
	store, ok := byLocation[creds]
	if !ok || store.Format != "JCEKS" || store.Algorithm != "unknown" || store.Fingerprint != "" ||
		store.Metadata["keystore_secret_keys"] != "2" || store.Metadata["keystore_state"] != "read" || store.Metadata["integrity_verified"] != "true" {
		t.Fatalf("secret-only store = %+v", store)
	}
}
