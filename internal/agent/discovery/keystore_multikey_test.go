// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// X2-L1: the host agent reports every key alias of a Java PKCS12 keystore
// (made by keytool, opened with Java's default store password), each at
// <file>#<alias> with its type, size and chain, the 1024-bit key weak, and
// the keystore's trusted entry counted on each.
func TestKeystoreSourceReportsEveryAliasOfAJavaPKCS12X2L1(t *testing.T) {
	data, err := os.ReadFile("../../crypto/pfx/testdata/x2l1-java-multi-key.p12")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "app.p12")
	if err := os.WriteFile(path, data, 0o600); err != nil { // #nosec G703 -- the test writes its fixture into its own t.TempDir() (CWE-22)
		t.Fatal(err)
	}
	found, err := NewKeystoreSource(nil, dir).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][3]string{ // key type, size, chain length
		"tomcat": {"RSA", "2048", "2"},
		"api-ec": {"ECDSA", "256", "1"},
		"legacy": {"RSA", "1024", "1"},
	}
	if len(found) != len(want) {
		t.Fatalf("found %d keystore findings; want one per alias (%d): %+v", len(found), len(want), found)
	}
	for _, f := range found {
		alias := f.Metadata["keystore_alias"]
		w, ok := want[alias]
		if !ok || f.Location != path+"#"+alias || f.Format != "PKCS12" || f.Metadata["keystore_state"] != "read" ||
			f.Metadata["key_type"] != w[0] || f.Metadata["key_size_bits"] != w[1] || f.Metadata["chain_length"] != w[2] ||
			f.Metadata["keystore_trusted_certificates"] != "1" || f.Metadata["integrity_verified"] != "true" || f.Fingerprint == "" {
			t.Fatalf("finding for %q = %+v", alias, f)
		}
		if (len(f.WeakReasons) > 0) != (alias == "legacy") {
			t.Fatalf("%s weak reasons = %v", alias, f.WeakReasons)
		}
		delete(want, alias)
	}
}
