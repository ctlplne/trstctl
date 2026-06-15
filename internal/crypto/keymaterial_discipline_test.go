package crypto_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This is the CRYPTO-003 regression guard for AN-8 on the crypto core and signer.
//
// AN-8 says secret key material lives in []byte (mlock'able, zeroizable), never in
// string. The crypto core already honors this by convention — every private key
// lives in a secret.Buffer (locked.go, pqc.go, slhdsa.go) and every transient
// unsealed copy is a []byte that is wiped — but the package-wide
// //trustctl:keymaterial marker cannot be applied here: the marked-package rule
// flags ANY string-backed field/param (so it would false-positive on the
// non-secret crypto.Algorithm enum, JWK base64 coordinates, file paths, and key
// handles these packages legitimately carry). This test pins the real invariant
// precisely: in the key-handling packages, no field whose NAME denotes secret key
// material may be string-typed. A regression that added e.g. `privateKeyPEM
// string` to the crypto core or the signer — the exact gap the audit named — fails
// here, while the legitimate non-secret strings are left alone.
//
// It is an AST check (go/parser), so it sees the real source, not a proxy.
func TestKeyMaterialFieldsAreNotStrings(t *testing.T) {
	// Package directories that hold or handle private-key material, relative to
	// this file (internal/crypto).
	pkgDirs := []string{
		".",          // internal/crypto (LockedSigner, SLHDSASigner, software keys, ...)
		"byok",       // BYOK/HSM key lifecycle (EXC-CRYPTO-01): material in LockedSigner/LocalKEK/[]byte
		"kek",        // KEK loader
		"pqc",        // post-quantum signer
		"seal",       // envelope-encryption KEK/DEK
		"secret",     // the locked secret buffer primitive
		"../signing", // the isolated signer (keystore, server)
	}

	// secretNameHints are substrings of a field/param name that denote secret key
	// material. A field so named must not be string-typed (AN-8).
	secretNameHints := []string{
		"privatekey", "privkey", "secretkey", "signingkey",
		"keymaterial", "keybytes", "keyder", "keypem", "keyseed",
		"password", "passphrase", "secretaccesskey",
	}
	// allowNames are names that contain a hint substring but are NOT secret key
	// material (avoid false positives on identifiers/handles).
	allowName := func(lower string) bool {
		// "keyid", "keyidentifier", "keyhandle" are non-secret handles; "publickey"
		// is public; algorithm/usage are enums.
		for _, ok := range []string{"keyid", "keyhandle", "publickey", "keyusage", "keyalgorithm"} {
			if strings.Contains(lower, ok) {
				return true
			}
		}
		return false
	}

	isSecretName := func(name string) bool {
		l := strings.ToLower(name)
		if allowName(l) {
			return false
		}
		for _, h := range secretNameHints {
			if strings.Contains(l, h) {
				return true
			}
		}
		return false
	}

	// isStringy reports whether an ast type expression is (or is built from) the
	// literal identifier "string" — the syntactic forms a secret could hide behind.
	var isStringy func(expr ast.Expr) bool
	isStringy = func(expr ast.Expr) bool {
		switch e := expr.(type) {
		case *ast.Ident:
			return e.Name == "string"
		case *ast.StarExpr:
			return isStringy(e.X)
		case *ast.ArrayType:
			return isStringy(e.Elt)
		case *ast.MapType:
			return isStringy(e.Value)
		default:
			return false
		}
	}

	checked := 0
	for _, dir := range pkgDirs {
		fset := token.NewFileSet()
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			checked++
			ast.Inspect(f, func(n ast.Node) bool {
				field, ok := n.(*ast.Field)
				if !ok {
					return true
				}
				if !isStringy(field.Type) {
					return true
				}
				for _, id := range field.Names {
					if isSecretName(id.Name) {
						t.Errorf("%s: field/param %q is string-typed but its name denotes secret key material; use []byte / secret.Buffer (AN-8, CRYPTO-003)",
							fset.Position(id.Pos()), id.Name)
					}
				}
				return true
			})
		}
	}
	if checked == 0 {
		t.Fatal("no source files scanned; the key-handling package paths are wrong — revisit this test")
	}
}
