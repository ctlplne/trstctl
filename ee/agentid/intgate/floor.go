// SPDX-License-Identifier: LicenseRef-trstctl-EE

package intgate

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// floor.go is the lexical engine of the gate. It works purely from source (AST +
// identifier scan), needs no whole-program load, and therefore runs everywhere the
// floor test runs. It provides:
//
//   - ExportedConstructors: enumerate every exported constructor/factory/Attach* in a
//     package's non-test .go files (the live AST -- the drift guard compares this to
//     the static Inventory).
//   - NonTestCallers: find non-test .go references to a constructor across the module
//     (the "does it have a production caller?" question the PCAS gate answers with
//     grep; here done over the parsed module so a comment or string match can't be
//     mistaken for a caller).
//
// A "constructor" is an exported top-level func whose name begins with New or Attach
// (the card's "exported constructor / factory / Attach*"). We also admit the exact
// name "New" (a package-level factory named New, e.g. store.New / brokerstore.New).

// moduleRoot walks up from the intgate package directory to the directory containing
// go.mod (the module root), so the gate locates sources regardless of the process cwd
// (`go test` runs with cwd = the package dir; `make` may run from elsewhere).
func moduleRoot() (string, error) {
	// The runtime working directory of `go test ./ee/agentid/intgate/...` is the package
	// directory itself. Walk up to the module root.
	start, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := start
	for {
		if fi, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !fi.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("intgate: go.mod not found walking up from %s", start)
		}
		dir = parent
	}
}

// isConstructorName reports whether name is an exported constructor/factory identifier:
// exactly "New", or "New"/"Attach" followed by an uppercase letter (New<Name> /
// Attach<Name>). A method (receiver) is excluded by the caller (only top-level funcs).
func isConstructorName(name string) bool {
	if name == "New" {
		return true
	}
	for _, pfx := range []string{"New", "Attach"} {
		if strings.HasPrefix(name, pfx) && len(name) > len(pfx) {
			r := rune(name[len(pfx)])
			if r >= 'A' && r <= 'Z' {
				return true
			}
		}
	}
	return false
}

// isTestOnlyFile reports whether a file path is test-only for gate purposes: a
// *_test.go file, or a file under a /mock, /fake, /testkit directory or a testdata/
// tree. Build-tag-gated test-only files are handled separately (fileHasTestOnlyBuildTag).
func isTestOnlyFile(relPath string) bool {
	if strings.HasSuffix(relPath, "_test.go") {
		return true
	}
	// Normalize separators for the segment check.
	segs := strings.Split(filepath.ToSlash(relPath), "/")
	for _, s := range segs {
		switch s {
		case "mock", "mocks", "fake", "fakes", "testkit", "testdata":
			return true
		}
	}
	return false
}

// testOnlyBuildTags are build constraints that mark a file as test-only substrate. A
// file carrying any of these is not a production caller even if it is not named
// *_test.go. (The AGID sources use none today; this future-proofs the gate against a
// //go:build testkit helper being counted as production.)
var testOnlyBuildTags = []string{"testkit", "testonly", "test_only"}

// fileHasTestOnlyBuildTag reports whether the file's //go:build / +build lines contain
// a test-only tag from testOnlyBuildTags.
func fileHasTestOnlyBuildTag(fset *token.FileSet, f *ast.File) bool {
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			txt := c.Text
			if !strings.HasPrefix(txt, "//go:build") && !strings.HasPrefix(txt, "// +build") {
				continue
			}
			for _, tag := range testOnlyBuildTags {
				if strings.Contains(txt, tag) {
					return true
				}
			}
		}
	}
	return false
}

// pkgDir returns the absolute directory of a module-relative import path.
func pkgDir(root, importRelPath string) string {
	return filepath.Join(root, filepath.FromSlash(importRelPath))
}

// ExportedConstructors parses the non-test .go files of the package at module-relative
// importRelPath and returns the names of its exported constructors/factories/Attach*
// (top-level funcs only; methods excluded). Files with a test-only build tag are
// skipped (their constructors are not production surface). Missing package => empty.
func ExportedConstructors(root, importRelPath string) ([]string, error) {
	dir := pkgDir(root, importRelPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	fset := token.NewFileSet()
	var names []string
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		full := filepath.Join(dir, e.Name())
		f, err := parser.ParseFile(fset, full, nil, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("intgate: parse %s: %w", full, err)
		}
		if fileHasTestOnlyBuildTag(fset, f) {
			continue
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil { // top-level funcs only
				continue
			}
			name := fn.Name.Name
			if !fn.Name.IsExported() || !isConstructorName(name) {
				continue
			}
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	return names, nil
}

// CallerRef is a single non-test .go reference to a constructor: the file (module-
// relative) and the 1-based line. It is the evidence a constructor has a production
// caller.
type CallerRef struct {
	File string
	Line int
}

// callIndex is a one-pass, PACKAGE-QUALIFIED index of every non-test call expression
// under a set of search roots. Calls are keyed by the RESOLVED callee package path plus
// the callee name ("calleePkgPath\x00Name"), so a call of the module-local
// store.New(...) is NEVER confused with errors.New(...) or keystore.New(...): a bare
// call N(...) is attributed to the CALLER'S OWN package; a selector X.N(...) is
// attributed to the import path X resolves to via the file's import table. This is the
// AST equivalent of the PCAS gate's fully-qualified grep (agidstore.New(), not New()).
//
// Building it once and reusing it across all constructors turns the gate from
// O(constructors * files) parses into a single O(files) pass -- essential given ~800
// non-test .go files under ee/agentid+cmd+internal.
type callIndex struct {
	root string
	// callsByKey maps "calleePkgPath\x00Name" -> the non-test CallerRefs.
	callsByKey map[string][]CallerRef
	// funcSpanByKey maps "pkgPath\x00Name" -> the top-level func declaration's span, so a
	// call located INSIDE a constructor's own body (self-reference / recursion) can be
	// excluded precisely, WITHOUT excluding a sibling function in the same file that
	// legitimately calls it (e.g. NewBrokerPrecondition -> NewMemoryIdempotencer, both in
	// precondition.go).
	funcSpanByKey map[string]funcSpan
}

// funcSpan is a top-level func declaration's location: its module-relative file and the
// inclusive 1-based line range it occupies.
type funcSpan struct {
	File      string
	StartLine int
	EndLine   int
}

// callIndexCache memoizes callIndex by the search-root key, so the floor, seam, and
// proxy tests share one parse of the module within a `go test` process.
var callIndexCache = map[string]*callIndex{}

func searchRootsKey(root string, searchRoots []string) string {
	return root + "\x00" + strings.Join(searchRoots, "\x00")
}

// calleeKey is the index/lookup key for a call of Name in package pkgPath (the full
// module-qualified import path, e.g. trstctl.com/trstctl/ee/agentid/delegation/store).
func calleeKey(pkgPath, name string) string { return pkgPath + "\x00" + name }

// pkgPathOfFile returns the full import path of the package that OWNS a module-relative
// .go file, i.e. modulePath + "/" + dir(relFile). (All first-party packages live at
// their directory path under the module root.)
func pkgPathOfFile(relFile string) string {
	dir := filepath.ToSlash(filepath.Dir(relFile))
	if dir == "." || dir == "" {
		return modulePath
	}
	return modulePath + "/" + dir
}

// importAliasMap returns, for a parsed file, a map from the local package identifier
// (explicit alias, or the imported package's assumed base name when unaliased) to the
// imported package's full import path. Only imports under the module root are recorded
// (third-party imports can't name a first-party constructor). For an unaliased import
// we assume the local name is the path's last segment, which holds for every first-party
// package in this repo (package name == dir base; verified by the build).
func importAliasMap(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, imp := range f.Imports {
		if imp.Path == nil {
			continue
		}
		p := strings.Trim(imp.Path.Value, `"`)
		if p != modulePath && !hasPathPrefix(p, modulePath) {
			continue // not a first-party package
		}
		local := ""
		if imp.Name != nil {
			local = imp.Name.Name // explicit alias (incl. "_" / "." which we then skip)
		} else {
			local = lastPathSegment(p)
		}
		if local == "" || local == "_" || local == "." {
			continue
		}
		out[local] = p
	}
	return out
}

// buildCallIndex walks searchRoots once, parses each non-test .go file (skipping
// *_test.go, /mock, /fake, /testkit, testdata, and test-only-build-tag files), resolves
// each call's callee package, and records "calleePkgPath\x00Name" -> CallerRef.
func buildCallIndex(root string, searchRoots []string) (*callIndex, error) {
	idx := &callIndex{root: root, callsByKey: map[string][]CallerRef{}, funcSpanByKey: map[string]funcSpan{}}
	for _, sr := range searchRoots {
		base := filepath.Join(root, filepath.FromSlash(sr))
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "mock", "mocks", "fake", "fakes", "testkit", "testdata":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)
			if isTestOnlyFile(rel) {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if perr != nil {
				return fmt.Errorf("intgate: parse %s: %w", path, perr)
			}
			if fileHasTestOnlyBuildTag(fset, f) {
				return nil
			}
			ownPkg := pkgPathOfFile(rel)
			aliases := importAliasMap(f)
			// Record top-level func declaration spans (for precise self-reference exclusion).
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil {
					continue
				}
				start := fset.Position(fn.Pos())
				end := fset.Position(fn.End())
				idx.funcSpanByKey[calleeKey(ownPkg, fn.Name.Name)] = funcSpan{File: rel, StartLine: start.Line, EndLine: end.Line}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				calleePkg, name, ok := resolveCallee(call.Fun, ownPkg, aliases)
				if !ok {
					return true
				}
				pos := fset.Position(call.Pos())
				idx.callsByKey[calleeKey(calleePkg, name)] = append(idx.callsByKey[calleeKey(calleePkg, name)], CallerRef{File: rel, Line: pos.Line})
				return true
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return idx, nil
}

// resolveCallee resolves a call expression's function to (calleePkgPath, name). A bare
// identifier N is attributed to ownPkg (a same-package call); a selector X.N is
// attributed to aliases[X] when X is a known first-party import alias. Any other form
// (X not a first-party import, method value, func literal, etc.) yields ok=false so it
// is not attributed to a first-party constructor.
func resolveCallee(fun ast.Expr, ownPkg string, aliases map[string]string) (pkgPath, name string, ok bool) {
	switch fn := fun.(type) {
	case *ast.Ident:
		return ownPkg, fn.Name, true
	case *ast.SelectorExpr:
		xIdent, isIdent := fn.X.(*ast.Ident)
		if !isIdent {
			return "", "", false
		}
		p, known := aliases[xIdent.Name]
		if !known {
			return "", "", false
		}
		return p, fn.Sel.Name, true
	}
	return "", "", false
}

// getCallIndex returns the memoized index for (root, searchRoots), building it on first
// use.
func getCallIndex(root string, searchRoots []string) (*callIndex, error) {
	key := searchRootsKey(root, searchRoots)
	if idx, ok := callIndexCache[key]; ok {
		return idx, nil
	}
	idx, err := buildCallIndex(root, searchRoots)
	if err != nil {
		return nil, err
	}
	callIndexCache[key] = idx
	return idx, nil
}

// NonTestCallers returns the non-test .go references that CALL the constructor Name
// DEFINED IN the package that owns defFile, excluding defFile itself (so the func's own
// declaration/self-reference is never counted). Matching is PACKAGE-QUALIFIED: a bare
// call in the defining package or a selector call through a first-party import alias
// resolving to the defining package, and nothing else (so store.New is not conflated
// with errors.New). Backed by the shared one-pass callIndex, so repeated queries are
// O(1). searchRoots limits the walk (e.g. ee/agentid, cmd, internal).
func NonTestCallers(root, name, defFile string, searchRoots []string) ([]CallerRef, error) {
	idx, err := getCallIndex(root, searchRoots)
	if err != nil {
		return nil, err
	}
	defRel := filepath.ToSlash(defFile)
	defPkg := pkgPathOfFile(defRel)
	span, haveSpan := idx.funcSpanByKey[calleeKey(defPkg, name)]
	var refs []CallerRef
	for _, r := range idx.callsByKey[calleeKey(defPkg, name)] {
		// Exclude ONLY references inside the constructor's own declaration body (self-
		// reference / recursion), not every reference in the same file -- a sibling
		// function in the same file that calls it IS a genuine caller (e.g.
		// NewBrokerPrecondition -> NewMemoryIdempotencer, both in precondition.go).
		if haveSpan && r.File == span.File && r.Line >= span.StartLine && r.Line <= span.EndLine {
			continue
		}
		refs = append(refs, r)
	}
	return refs, nil
}

// ControlPlaneCallers returns the non-test callers of a constructor that live OUTSIDE
// the constructor's own package -- i.e. genuine downstream callers on the cmd/internal/
// cross-package attach path, excluding same-package helpers (like the verify package's
// own sample.go SDK helper calling verify.NewLocalPolicy). Used for the DEFERRED-tier
// assertion, whose invariant is "no CONTROL-PLANE caller", not "no caller at all".
func ControlPlaneCallers(root, name, defFile string, searchRoots []string) ([]CallerRef, error) {
	refs, err := NonTestCallers(root, name, defFile, searchRoots)
	if err != nil {
		return nil, err
	}
	defPkg := pkgPathOfFile(filepath.ToSlash(defFile))
	var out []CallerRef
	for _, r := range refs {
		if pkgPathOfFile(r.File) == defPkg {
			continue // same-package helper, not a control-plane caller
		}
		out = append(out, r)
	}
	return out, nil
}

// defaultSearchRoots are the module subtrees a production caller could live in: the
// AGID family itself (an in-scope constructor calling another is a legitimate non-test
// caller, e.g. NewSignerGate -> NewGate), plus cmd (the ee_attach seams) and internal
// (the feature-neutral server/broker wiring the seam configures). It mirrors the PCAS
// gate's ROOTS=(ee internal cmd).
var defaultSearchRoots = []string{"ee/agentid", "cmd", "internal"}
