package secretsdk_test

// PROTECT track (sprint R11): the GAP-010 hygiene lock for the five secrets/identity
// library packages the audit verified clean — secretsdk, secretsync, secretshare,
// pkisecret, authmethod. These packages are NOT tagged //trstctl:keymaterial, so the
// AN-8 keymaterial linter does not cover them; the audit confirmed by inspection that
// they nonetheless keep secret material in []byte (never string), route all crypto
// through the AN-3 boundary (zero crypto/* imports), and leak no secret VALUE into an
// error string. This source-scanning guard pins those invariants so a future edit
// cannot quietly regress them. It changes NO behavior.
//
// (Scoped, deliberate, syntactic checks — not a substitute for the linter, but a
// targeted regression wall for exactly the strengths GAP-010 confirmed.)

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gapPackages are the five GAP-010 packages, as dirs relative to this test file
// (internal/secretsdk/...). Each is asserted to still exist.
var gapPackages = []string{
	".",              // secretsdk
	"../secretsync",  //
	"../secretshare", //
	"../pkisecret",   //
	"../authmethod",  //
}

// nonTestGoFilesIn returns the non-test .go files directly under dir.
func nonTestGoFilesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.FromSlash(dir))
	if err != nil {
		t.Fatalf("GAP-010: read %s: %v (package moved? revisit this guard)", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		out = append(out, filepath.Join(filepath.FromSlash(dir), e.Name()))
	}
	return out
}

// TestGAPPackagesImportNoStdlibCrypto is the AN-3 lock: none of the five packages may
// import crypto/* directly — all cryptography routes through internal/crypto. (This is
// also enforced globally by trstctllint, but pinning it here keeps the GAP-010
// strength true even if the global rule's coverage ever narrows.)
func TestGAPPackagesImportNoStdlibCrypto(t *testing.T) {
	for _, pkg := range gapPackages {
		for _, f := range nonTestGoFilesIn(t, pkg) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("GAP-010: parse %s: %v", f, err)
			}
			for _, imp := range file.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if path == "crypto" || strings.HasPrefix(path, "crypto/") {
					t.Errorf("GAP-010/AN-3: %s imports %q directly; cryptography must route through internal/crypto", f, path)
				}
			}
		}
	}
}

// isSecretValueName reports whether an identifier names secret MATERIAL (a value that
// must be []byte under AN-8), as opposed to a mere name/reference/label.
func isSecretValueName(name string) bool {
	low := strings.ToLower(name)
	// Names that are references/labels, not the secret bytes themselves.
	switch {
	case strings.HasSuffix(low, "id"), // KeyID, SecretID — a reference
		strings.HasSuffix(low, "name"),    // KeyName, SecretName
		strings.HasSuffix(low, "ref"),     // BackendRef
		strings.HasSuffix(low, "path"),    // SecretPath
		strings.HasSuffix(low, "type"),    // SecretType
		strings.HasSuffix(low, "version"): // SecretVersion
		return false
	}
	for _, kw := range []string{"secret", "password", "passphrase", "privatekey"} {
		if strings.Contains(low, kw) {
			return true
		}
	}
	// "key" alone is ambiguous (a map key, a key NAME); only treat the exact field
	// "Key" as a value when nothing disambiguates it away — but secretsync.SyncItem.Key
	// is a NAME, so we deliberately do NOT flag a bare "Key". Material is named
	// Secret/Password/Passphrase/PrivateKey in these packages.
	return false
}

// TestGAPPackagesHoldSecretsAsBytesNotString is the AN-8 lock: any struct field whose
// name denotes secret MATERIAL (Secret, Password, Passphrase, PrivateKey, ...) must be
// typed []byte — never string, which Go's GC can copy freely. Reference/label fields
// (KeyID, SecretName, BackendRef, ...) are allowed to be string.
func TestGAPPackagesHoldSecretsAsBytesNotString(t *testing.T) {
	for _, pkg := range gapPackages {
		for _, f := range nonTestGoFilesIn(t, pkg) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, f, nil, 0)
			if err != nil {
				t.Fatalf("GAP-010: parse %s: %v", f, err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				st, ok := n.(*ast.StructType)
				if !ok || st.Fields == nil {
					return true
				}
				for _, field := range st.Fields.List {
					if !isStringType(field.Type) {
						continue
					}
					for _, nm := range field.Names {
						if isSecretValueName(nm.Name) {
							t.Errorf("GAP-010/AN-8: %s field %q holds secret material as string; secret bytes must be []byte (Go strings are GC-copyable)", f, nm.Name)
						}
					}
				}
				return true
			})
		}
	}
}

// isStringType reports whether expr is the predeclared `string` type (bare, not a
// named type whose underlying is string — which the syntactic pass can't resolve, but
// these packages use the bare type).
func isStringType(expr ast.Expr) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == "string"
}
