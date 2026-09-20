// SPDX-License-Identifier: BUSL-1.1

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

// TestSecretBufferBytesStaysDeadInCoreCryptoKeyPaths is guard ARCH-014, the core
// counterpart of guard ARCH-013 on the editions side of the fence.
//
// secret.Buffer.Bytes() returns a slice into the locked region and releases the
// buffer lock BEFORE the caller dereferences it, so a concurrent Destroy can wipe
// and (on Linux) munmap that region while the caller is still reading it. The
// correct read is secret.Buffer.Use, which holds the read side of the lock for the
// whole borrow, so Destroy waits rather than unmapping memory out from under it.
//
// ARCH-013 covers exactly one package. It was easy to read it as repo-wide
// coverage, and that misreading is exactly how five reachable Bytes() reads
// survived the first migration -- in ca.digestSigner, ca.lockedKey.sign,
// seal.LocalKEK.WithKey, seal.LocalKEK.gcm and crypto.SignAuthorizer.Authorize.
// Every one of those keys is custodied by the isolated signer (AN-4), which serves
// Sign and DestroyKey concurrently: precisely the case Bytes() is unsafe for.
//
// This guard walks ALL of internal/crypto rather than one package, so a new
// subpackage is covered the day it is added instead of the day someone remembers.
// It discovers the *secret.Buffer field names from the AST per package and then
// fails on any read of one through Bytes(), so a newly added buffer field is
// covered automatically too.
//
// Converting a Bytes() to a Use() is not always mechanical: Use holds a
// sync.RWMutex read lock and is NOT reentrant, so a borrow that calls back into
// caller-supplied code which touches the same buffer will deadlock behind a queued
// Destroy. Where that risk exists, keep the borrow around the copy-out (a parse, a
// key schedule, a MAC) and run the callback outside it.
func TestSecretBufferBytesStaysDeadInCoreCryptoKeyPaths(t *testing.T) {
	root := cryptoRoot(t)

	var (
		scanned   int
		bytesHits []string
		useHits   []string
		anyFields bool
	)
	for _, dir := range goPackageDirs(t, root) {
		fset := token.NewFileSet()
		files := parseShippedSources(t, fset, dir)
		if len(files) == 0 {
			continue
		}
		scanned++
		fields := secretBufferFieldNames(files)
		if len(fields) == 0 {
			continue
		}
		anyFields = true
		b, u := bufferReads(fset, files, fields)
		bytesHits = append(bytesHits, b...)
		useHits = append(useHits, u...)
	}

	if scanned == 0 {
		t.Fatal("ARCH-014: parsed no packages under internal/crypto; the guard is looking in the " +
			"wrong place and would pass vacuously -- re-point it rather than deleting it")
	}
	if !anyFields {
		t.Fatal("ARCH-014: found no *secret.Buffer fields anywhere under internal/crypto; either the " +
			"locked key material moved or this guard stopped seeing it -- re-point the guard")
	}
	if len(bytesHits) > 0 {
		t.Fatalf("ARCH-014: %d locked-key read(s) still go through secret.Buffer.Bytes():\n  %s\n"+
			"Bytes() releases the buffer lock before the caller reads the slice, so a concurrent "+
			"DestroyKey can wipe and unmap the region under a live Sign. Read the key inside "+
			"secret.Buffer.Use instead. Use is NOT reentrant: if the borrow would call back into "+
			"caller-supplied code, keep the borrow around the copy-out and run the callback outside it.",
			len(bytesHits), strings.Join(bytesHits, "\n  "))
	}
	if len(useHits) == 0 {
		t.Fatal("ARCH-014: no secret.Buffer.Use borrow found under internal/crypto; the key paths must " +
			"read private material inside a borrow, not by some other route around this guard")
	}
}

// cryptoRoot returns this package's own directory, which is internal/crypto.
func cryptoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("ARCH-014: getwd: %v", err)
	}
	return wd
}

// goPackageDirs returns root and every directory beneath it, so the guard covers
// subpackages added after it was written. testdata is skipped: it holds fixtures,
// not shipped key paths.
func goPackageDirs(t *testing.T, root string) []string {
	t.Helper()
	var dirs []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if name := d.Name(); path != root && (name == "testdata" || strings.HasPrefix(name, ".")) {
			return filepath.SkipDir
		}
		dirs = append(dirs, path)
		return nil
	})
	if err != nil {
		t.Fatalf("ARCH-014: walk internal/crypto: %v", err)
	}
	return dirs
}

// parseShippedSources parses the non-test Go sources in dir. Test files are
// excluded on purpose: the guard is about the shipped key paths, not fixtures,
// which legitimately reach for Bytes() to assert on the raw material.
func parseShippedSources(t *testing.T, fset *token.FileSet, dir string) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ARCH-014: read %s: %v", dir, err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("ARCH-014: parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	return files
}

// secretBufferFieldNames returns the names of struct fields declared as
// *secret.Buffer in the given files.
func secretBufferFieldNames(files []*ast.File) map[string]bool {
	fields := map[string]bool{}
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok || st.Fields == nil {
				return true
			}
			for _, f := range st.Fields.List {
				star, ok := f.Type.(*ast.StarExpr)
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
				for _, name := range f.Names {
					fields[name.Name] = true
				}
			}
			return true
		})
	}
	return fields
}

// bufferReads returns the positions of Bytes() and Use() calls made on any of the
// named *secret.Buffer fields. It matches on the selector shape (x.field.Method),
// which is how every such read in this tree is written.
func bufferReads(fset *token.FileSet, files []*ast.File, fields map[string]bool) (bytesCalls, useCalls []string) {
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
	return bytesCalls, useCalls
}
