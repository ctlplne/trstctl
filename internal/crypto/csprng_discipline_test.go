package crypto_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestCryptoSourceUsesNoMathRand is the CRYPTO-008 CSPRNG-discipline regression
// guard. Randomness inside the crypto boundary must come from a cryptographically
// secure source: key generation and AEAD nonces flow through crypto/rand
// (software.RandomBytes), and the only deterministic stream (internal/crypto/detrand)
// is a SHA-256 counter explicitly scoped to NON-secret, must-be-reproducible salts.
//
// The weak, predictable math/rand (and math/rand/v2) PRNG must never appear in
// non-test crypto source — a key or nonce derived from it would be guessable. The
// audit verified "0 math/rand hits on non-test crypto source" by hand; this test
// pins that invariant in CI so a regression (someone reaching for the convenient
// math/rand) fails the build instead of silently weakening the CSPRNG guarantee.
//
// It is an AST import check over the real source tree (go/parser), not a proxy,
// and walks every package under internal/crypto. _test.go files are exempt: a
// differential/property test may legitimately use math/rand to drive fuzz inputs.
func TestCryptoSourceUsesNoMathRand(t *testing.T) {
	// Root of the crypto boundary, relative to this file (internal/crypto).
	const root = "."
	banned := map[string]bool{
		"math/rand":    true,
		"math/rand/v2": true,
	}

	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip test-only and generated trees: testdata holds fuzz corpora and
			// fixtures, not production crypto.
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		scanned++
		for _, imp := range f.Imports {
			// imp.Path.Value includes the surrounding quotes.
			p := strings.Trim(imp.Path.Value, `"`)
			if banned[p] {
				t.Errorf("%s imports %q; crypto boundary source must use the crypto/rand CSPRNG (or detrand for non-secret reproducible salts), never the weak math/rand PRNG (AN-3/CRYPTO-008)",
					fset.Position(imp.Pos()), p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if scanned == 0 {
		t.Fatal("no crypto source files scanned; the guard is not meaningful — revisit the walk root")
	}
}
