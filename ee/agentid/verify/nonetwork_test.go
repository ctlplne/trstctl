// SPDX-License-Identifier: LicenseRef-trstctl-EE

package verify

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// nonetwork_test.go proves the OFFLINE property structurally (AGID-claim-7 / INV-A7):
// the verify path constructs NO network client and issues NO revocation-status
// query. It does this two ways that a future change cannot silently defeat:
//
//   - a SOURCE guard that parses every non-test .go file in this package and fails
//     if any imports a network package (net, net/http, net/url) or references a
//     dialing / status-query surface; and
//   - a DEPENDENCY guard (TestVerifyPackageDepsAreNetworkFree) that fails if the
//     package's own source names such a package.
//
// The carriage / crypto boundary packages this verifier consumes are themselves
// audited elsewhere; here we bound THIS package's verify path.

// forbiddenImports are packages a purely-offline verifier must never import.
var forbiddenImports = map[string]bool{
	"net":          true,
	"net/http":     true,
	"net/url":      true,
	"net/rpc":      true,
	"os/exec":      true,
	"database/sql": true,
}

// forbiddenSourcePatterns are CODE call surfaces (scanned after comments are
// stripped) that would indicate a network client or a live status query slipped
// into the verify path. They match identifiers/calls, not prose -- so this
// package's documentation, which names what it deliberately does NOT do
// (revocation-status queries, OCSP, CRL, jwks_uri fetching), does not trip the
// guard, while an actual net.Dial / http.Client / .Get( call does.
var forbiddenSourcePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bnet\.Dial\w*\(`),
	regexp.MustCompile(`\bhttp\.(Get|Post|Client|NewRequest|DefaultClient)\b`),
	regexp.MustCompile(`\bhttp\.Get\(`),
	regexp.MustCompile(`\.Dial\(`),
	regexp.MustCompile(`\bDefaultTransport\b`),
}

// packageGoFiles returns the non-test .go files of this package (the shipped
// verify path). The WASM subpackage lives in ./wasm and is checked too.
func packageGoFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	roots := []string{".", "wasm"}
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			files = append(files, filepath.Join(root, name))
		}
	}
	if len(files) == 0 {
		t.Fatal("no package .go files found to audit")
	}
	return files
}

// TestNoNetworkClientInVerifyPath parses every non-test source file in the verify
// package (and its WASM subpackage) and fails if any imports a network package or
// references a dialing / status-query surface. This is the structural proof that
// the verify path constructs no network client and issues no revocation-status
// query (AGID-claim-7 / INV-A7 offline property).
func TestNoNetworkClientInVerifyPath(t *testing.T) {
	fset := token.NewFileSet()
	for _, f := range packageGoFiles(t) {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		file, err := parser.ParseFile(fset, f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if forbiddenImports[path] {
				t.Errorf("%s imports forbidden network/offline-violating package %q (verify path must construct no network client)", f, path)
			}
		}
		// Source-surface scan over CODE ONLY (comments stripped), so prose naming
		// what the package deliberately avoids does not false-positive.
		code := stripComments(fset, src, f)
		for _, re := range forbiddenSourcePatterns {
			if loc := re.FindString(code); loc != "" {
				t.Errorf("%s references forbidden CODE surface %q (no network client / status query allowed in the verify path)", f, loc)
			}
		}
	}
}

// TestVerifyPackageDepsAreNetworkFree is a second, coarser guard: it asserts the
// package's own import set (across all non-test files) contains none of the
// forbidden network packages, independent of the regex surface scan above.
func TestVerifyPackageDepsAreNetworkFree(t *testing.T) {
	fset := token.NewFileSet()
	seen := map[string]bool{}
	for _, f := range packageGoFiles(t) {
		file, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, imp := range file.Imports {
			seen[strings.Trim(imp.Path.Value, `"`)] = true
		}
	}
	for bad := range forbiddenImports {
		if seen[bad] {
			t.Errorf("verify package imports %q, which a purely-offline verifier must not", bad)
		}
	}
}

// stripComments returns the file source with all comments removed, so the
// code-surface scan sees only executable code. It re-parses with comments and
// blanks out each comment span.
func stripComments(fset *token.FileSet, src []byte, filename string) string {
	file, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		// If it will not parse, fall back to the raw source (the import guard still runs).
		return string(src)
	}
	out := append([]byte(nil), src...)
	base := fset.File(file.Pos()).Base()
	for _, cg := range file.Comments {
		for _, c := range cg.List {
			start := int(c.Pos()) - base
			end := int(c.End()) - base
			if start < 0 || end > len(out) || start >= end {
				continue
			}
			for i := start; i < end; i++ {
				if out[i] != '\n' {
					out[i] = ' '
				}
			}
		}
	}
	return string(out)
}
