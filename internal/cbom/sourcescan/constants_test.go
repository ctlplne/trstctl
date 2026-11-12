// SPDX-License-Identifier: BUSL-1.1

package sourcescan_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/cbom/sourcescan"
)

// constantsRepository holds key sizes and curves that reach the generators
// through names: package constants in another file, constant expressions,
// locals assigned once, a variable assigned twice, a curve in a variable, one
// level of wrapper functions, a test package's look-alike constant, and Java
// and Python key-size names.
var constantsRepository = map[string]string{
	"internal/keys/config.go": `package keys

const (
	legacyBits = 1024
	modernBits = legacyBits * 3 // 3072
)

const bigBits int = 1 << 12

var fallbackBits = 512
`,
	"internal/keys/keys.go": `package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

func legacy() { rsa.GenerateKey(rand.Reader, legacyBits) }

func modern() { rsa.GenerateKey(rand.Reader, modernBits) }

func big() { rsa.GenerateKey(rand.Reader, int(bigBits)) }

func fallback() { rsa.GenerateKey(rand.Reader, fallbackBits) }

func local() {
	bits := 2048
	rsa.GenerateKey(rand.Reader, bits)
}

func reassigned() {
	n := 1024
	n = 4096
	rsa.GenerateKey(rand.Reader, n)
}

func curveInVariable() {
	curve := elliptic.P384()
	ecdsa.GenerateKey(curve, rand.Reader)
}

func newRSA(size int) (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, size) }

func newEC(c elliptic.Curve) (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(c, rand.Reader) }

func callers() {
	newRSA(1024)
	newRSA(modernBits - 1024)
	newEC(elliptic.P521())
}
`,
	"internal/keys/keys_x_test.go": `package keys_test

import (
	"crypto/rand"
	"crypto/rsa"
)

const legacyBits = 8192

func use() { rsa.GenerateKey(rand.Reader, legacyBits) }
`,
	"src/main/java/demo/Legacy.java": `package demo;
import java.security.KeyPairGenerator;
class Legacy {
  private static final int KEY_SIZE = 1024;
  void make() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(KEY_SIZE);
  }
}
`,
	"tools/legacy.py": `from cryptography.hazmat.primitives.asymmetric import rsa
KEY_BITS = 1024
key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)
`,
}

// X6-L2: the source scan follows a key size or curve through constants,
// constant expressions and names assigned once, across a package's files,
// and one level into a wrapper's callers; a variable assigned twice and a
// test package's own constant resolve to nothing they should not.
func TestScanFollowsKeySizesThroughConstantsX6L2(t *testing.T) {
	root := t.TempDir()
	for name, body := range constantsRepository {
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
	var got []string
	for _, u := range uses {
		got = append(got, u.File+":"+itoa(u.Line)+" "+u.Algorithm+" "+itoa(u.KeyBits)+" "+u.API)
	}
	sort.Strings(got)
	want := []string{
		"internal/keys/keys.go:10 RSA 1024 crypto/rsa.GenerateKey",
		"internal/keys/keys.go:12 RSA 3072 crypto/rsa.GenerateKey",
		"internal/keys/keys.go:14 RSA 4096 crypto/rsa.GenerateKey",
		"internal/keys/keys.go:16 RSA 512 crypto/rsa.GenerateKey",
		"internal/keys/keys.go:20 RSA 2048 crypto/rsa.GenerateKey",
		"internal/keys/keys.go:26 RSA 0 crypto/rsa.GenerateKey",
		"internal/keys/keys.go:31 ECDSA-P384 384 crypto/ecdsa.GenerateKey",
		"internal/keys/keys.go:34 RSA 0 crypto/rsa.GenerateKey",
		"internal/keys/keys.go:39 RSA 1024 crypto/rsa.GenerateKey via newRSA",
		"internal/keys/keys.go:40 RSA 2048 crypto/rsa.GenerateKey via newRSA",
		"internal/keys/keys.go:41 ECDSA-P521 521 crypto/ecdsa.GenerateKey via newEC",
		"internal/keys/keys_x_test.go:10 RSA 8192 crypto/rsa.GenerateKey",
		"src/main/java/demo/Legacy.java:6 RSA 1024 KeyPairGenerator.getInstance",
		"tools/legacy.py:3 RSA 1024 rsa.generate_private_key",
	}
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("uses:\n%s\n\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// The 1024-bit sizes found through names are weak in the inventory.
	bom, err := sourcescan.CBOM(uses, "4f1c2d3e-5a6b-4c7d-8e9f-0a1b2c3d4e5f")
	if err != nil {
		t.Fatal(err)
	}
	imported, err := cbom.ParseCycloneDXImport(bom, "source:acme/keys", cbom.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	weak := 0
	for _, f := range imported.Findings {
		if f.Algorithm == "RSA" && f.KeyBits == 1024 {
			if f.Class.Strength != cbom.StrengthWeak {
				t.Fatalf("RSA-1024 at %s classified %q", f.Location, f.Class.Strength)
			}
			weak++
		}
	}
	if weak != 4 {
		t.Fatalf("RSA-1024 findings = %d; want 4 (package constant, wrapper call, Java, Python)", weak)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
