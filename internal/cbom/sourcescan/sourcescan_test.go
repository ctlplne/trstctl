// SPDX-License-Identifier: BUSL-1.1

package sourcescan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/cbom/sourcescan"
)

// SampleRepository is a small repository with RSA and ECDH in Go, Java and
// Python, and a vendored copy that must not be read.
var SampleRepository = map[string]string{
	"cmd/server/keys.go": `package main

import (
	"crypto/ecdh"
	"crypto/rand"
	stdrsa "crypto/rsa"
)

func keys() {
	_, _ = stdrsa.GenerateKey(rand.Reader, 2048)
	_, _ = ecdh.P256().GenerateKey(rand.Reader)
}
`,
	"src/main/java/demo/Keys.java": `package demo;
import java.security.KeyPairGenerator;
import javax.crypto.KeyAgreement;
class Keys {
  void make() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(3072);
    KeyAgreement a = KeyAgreement.getInstance("ECDH");
  }
}
`,
	"tools/keys.py": `from cryptography.hazmat.primitives.asymmetric import rsa, ec
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
shared = key2.exchange(ec.ECDH(), peer)
`,
	"vendor/lib/x.go": `package lib
import "crypto/rsa"
func f() { rsa.GenerateKey(nil, 1024) }
`,
}

// X6: a sample repository's RSA and ECDH uses are found with the file and
// line they come from, and import into the inventory with code as their source.
func TestScanFindsRSAAndECDHWithTheirSourceLines(t *testing.T) {
	root := t.TempDir()
	for name, body := range SampleRepository {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	uses, err := sourcescan.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]sourcescan.Use{}
	for _, u := range uses {
		got[u.File+":"+u.Algorithm] = u
	}
	for key, line := range map[string]int{
		"cmd/server/keys.go:RSA": 10, "cmd/server/keys.go:ECDH-P256": 11,
		"src/main/java/demo/Keys.java:RSA": 6, "src/main/java/demo/Keys.java:ECDH": 8,
		"tools/keys.py:RSA": 2, "tools/keys.py:ECDH": 6,
	} {
		if u, ok := got[key]; !ok || u.Line != line {
			t.Fatalf("%s at line %d: got %+v (all %+v)", key, line, u, uses)
		}
	}
	if got["cmd/server/keys.go:RSA"].KeyBits != 2048 || got["src/main/java/demo/Keys.java:RSA"].KeyBits != 3072 || got["tools/keys.py:RSA"].KeyBits != 2048 {
		t.Fatalf("key sizes: %+v", uses)
	}
	for _, u := range uses {
		if u.File == "vendor/lib/x.go" {
			t.Fatal("a vendored file was scanned")
		}
	}

	doc, err := sourcescan.CBOM(uses, "8a6f2c1e-1b2d-4e3f-9a0b-1c2d3e4f5a6b")
	if err != nil {
		t.Fatal(err)
	}
	bom, err := cbom.ParseCycloneDXImport(doc, "source:demo-repo", cbom.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	locations := map[string]bool{}
	for _, f := range bom.Findings {
		locations[f.Location+"|"+f.Algorithm] = true
	}
	for _, want := range []string{
		"source:demo-repo:cmd/server/keys.go:10|RSA", "source:demo-repo:cmd/server/keys.go:11|ECDH-P256",
		"source:demo-repo:src/main/java/demo/Keys.java:8|ECDH", "source:demo-repo:tools/keys.py:2|RSA",
	} {
		if !locations[want] {
			t.Fatalf("imported findings lack %s: %v", want, locations)
		}
	}
}
