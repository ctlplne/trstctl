// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// X2-L4R: --inventory-java's paths reach the library source, and a Java
// installation's finding carries its security providers in order; a jar's
// carries none.
func TestJavaInventoryFindingsCarryTheirProvidersX2L4R(t *testing.T) {
	home := filepath.Join(t.TempDir(), "java-25-openjdk")
	for name, body := range map[string]string{
		"release":                     "IMPLEMENTOR=\"Alpine\"\nJAVA_VERSION=\"25.0.5.0.3\"\n",
		"conf/security/java.security": "security.provider.1=SUN\nsecurity.provider.3=SunEC\nsecurity.provider.2=SunRsaSign\nsecurity.provider.4=SunJSSE\n",
		"lib/modules":                 "jimage\x00TLS_AES_128_GCM_SHA256\x00X25519MLKEM768\x00",
	} {
		path := filepath.Join(home, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	found, err := cryptoLibrarySource(nil, nil, splitList(home)).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var java []map[string]string
	for _, f := range cryptoLibraryInventoryFindings(found) {
		if f.Metadata["library"] == "java" {
			java = append(java, f.Metadata)
		}
	}
	if len(java) != 1 || java[0]["library_version"] != "25.0.5.0.3" || java[0]["pq_hybrid_x25519mlkem768"] != "yes" ||
		java[0]["java_security_providers"] != "SUN, SunRsaSign, SunEC, SunJSSE" {
		t.Fatalf("Java findings = %+v", java)
	}
}
