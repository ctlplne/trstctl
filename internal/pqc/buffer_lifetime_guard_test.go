// SPDX-License-Identifier: BUSL-1.1

package pqc

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestPQCSecretBufferBytesStaysDeadInKeyPaths is guard ARCH-013.
//
// secret.Buffer.Bytes() hands the caller a slice into the locked region and releases the
// buffer lock BEFORE the caller dereferences it, so a concurrent Destroy can wipe and (on
// Linux) munmap that region while the caller is still reading it. Every private key this
// package holds is custodied by the isolated signer -- cmd/trstctl-signer/ee_attach.go
// attaches signing.WithKeyFactory(NewSignerKeyFactory()) -- and the signer serves Sign and
// DestroyKey concurrently, which is exactly the case Bytes() is documented as unsafe for.
// The correct read is secret.Buffer.Use, which holds the read side of the buffer lock for
// the whole borrow so Destroy waits instead of unmapping memory out from under it.
//
// This guard keeps the class dead rather than letting it be fixed a third time: it
// discovers the *secret.Buffer fields in this package from the AST, then fails if any of
// them is read through Bytes(). A newly added buffer field is covered automatically.
func TestPQCSecretBufferBytesStaysDeadInKeyPaths(t *testing.T) {
	fset := token.NewFileSet()
	files := parsePackageSources(t, fset)

	fields := secretBufferFieldNames(files)
	if len(fields) == 0 {
		t.Fatal("ARCH-013: found no *secret.Buffer fields in package pqc; either the key material moved " +
			"or this guard stopped seeing it -- re-point the guard rather than letting it pass vacuously")
	}

	var bytesCalls, useCalls []string
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			method, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			field, ok := method.X.(*ast.SelectorExpr)
			if !ok || !fields[field.Sel.Name] {
				return true
			}
			where := fset.Position(call.Pos()).String()
			switch method.Sel.Name {
			case "Bytes":
				bytesCalls = append(bytesCalls, where)
			case "Use":
				useCalls = append(useCalls, where)
			}
			return true
		})
	}

	if len(bytesCalls) > 0 {
		t.Fatalf("ARCH-013: %d locked-key read(s) still go through secret.Buffer.Bytes():\n  %s\n"+
			"Bytes() releases the buffer lock before the caller reads the slice, so a concurrent "+
			"DestroyKey can wipe and unmap the region under a live Sign. Read the key inside "+
			"secret.Buffer.Use instead. Use is NOT reentrant, so check for nesting before converting.",
			len(bytesCalls), strings.Join(bytesCalls, "\n  "))
	}
	if len(useCalls) == 0 {
		t.Fatal("ARCH-013: no secret.Buffer.Use borrow found in package pqc; the key paths must read " +
			"private material inside a borrow, not by some other route around this guard")
	}
}

// parsePackageSources parses this package's non-test Go sources. Test files are excluded
// on purpose: the guard is about the shipped key paths, not about fixtures.
func parsePackageSources(t *testing.T, fset *token.FileSet) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ARCH-013: read package dir: %v", err)
	}
	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("ARCH-013: parse %s: %v", name, err)
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		t.Fatal("ARCH-013: no non-test sources found in package pqc")
	}
	return files
}

// secretBufferFieldNames returns the struct field names declared as *secret.Buffer across
// the given files, so the guard tracks the locked-key fields that actually exist instead
// of a hard-coded list that goes stale the moment a fourth key type is added.
func secretBufferFieldNames(files []*ast.File) map[string]bool {
	names := map[string]bool{}
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok || st.Fields == nil {
				return true
			}
			for _, field := range st.Fields.List {
				star, ok := field.Type.(*ast.StarExpr)
				if !ok {
					continue
				}
				sel, ok := star.X.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Buffer" {
					continue
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "secret" {
					continue
				}
				for _, fieldName := range field.Names {
					names[fieldName.Name] = true
				}
			}
			return true
		})
	}
	return names
}
