// SPDX-License-Identifier: LicenseRef-trstctl-EE

package intgate

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// modulePath is the Go module path; every import path below is module-relative.
const modulePath = "trstctl.com/trstctl"

// familyTree is the package tree this gate enumerates. Every non-test, non-generated
// .go file underneath it contributes its exported constructors; nothing is listed by
// hand, so a package added to the family is in scope the moment its first file lands.
const familyTree = "ee/succession"

// SanctionedSeams are the ONLY production roots through which an ee/succession
// constructor may become reachable. All three carry //go:build !trstctl_core, which the
// seam assertion re-checks so the edition fence cannot be dropped unnoticed.
var SanctionedSeams = []string{
	"cmd/trstctl/ee_attach.go",           // control plane: PCAS API + outbox worker attach
	"cmd/trstctl-signer/ee_attach.go",    // signer: in-signer minter attach
	"cmd/trstctl-agent/cosign_attach.go", // agent: co-signer service attach
}

// defaultSearchRoots are the trees scanned for non-test callers.
var defaultSearchRoots = []string{"cmd", "internal", "ee"}

// Constructor is one exported ee/succession constructor / factory / Attach* the gate
// governs. Pkg is the module-relative import path, Name the function identifier, File
// the defining file relative to the module root.
type Constructor struct {
	Pkg  string
	Name string
	File string
}

// Qualified renders "pkgbase.Name" for messages, e.g. "minter.NewHighWater".
func (c Constructor) Qualified() string {
	return lastPathSegment(c.Pkg) + "." + c.Name
}

// CallerRef is one non-test reference to a constructor.
type CallerRef struct {
	File string
	Line int
}

type callIndex struct {
	root       string
	callsByKey map[string][]CallerRef
	spansByKey map[string]funcSpan
}

type funcSpan struct {
	File      string
	StartLine int
	EndLine   int
}

var callIndexCache = map[string]*callIndex{}

func moduleRoot() (string, error) {
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
			return "", fmt.Errorf("pcas intgate: go.mod not found walking up from %s", start)
		}
		dir = parent
	}
}

// LiveConstructors enumerates every exported constructor under the family tree, sorted
// by package then name. It is derived entirely from the AST: there is no hand-curated
// mechanism list to fall out of date.
func LiveConstructors(root string) ([]Constructor, error) {
	pkgs, err := discoverInScopePackages(root)
	if err != nil {
		return nil, err
	}
	var out []Constructor
	seen := map[string]bool{}
	for _, pkg := range pkgs {
		ctors, err := ExportedConstructors(root, pkg)
		if err != nil {
			return nil, err
		}
		for _, c := range ctors {
			key := ctorKey(c.Pkg, c.Name)
			if seen[key] {
				return nil, fmt.Errorf("duplicate PCAS constructor key %s", humanKey(key))
			}
			seen[key] = true
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pkg == out[j].Pkg {
			return out[i].Name < out[j].Name
		}
		return out[i].Pkg < out[j].Pkg
	})
	return out, nil
}

// discoverInScopePackages walks the family tree and returns every module-relative
// package directory holding at least one non-test, non-generated, non-test-tagged file.
func discoverInScopePackages(root string) ([]string, error) {
	base := filepath.Join(root, filepath.FromSlash(familyTree))
	pkgs := map[string]bool{}
	err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "mock", "mocks", "fake", "fakes", "testkit", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if isTestOnlyFile(rel) {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("pcas intgate: parse %s: %w", rel, err)
		}
		if fileHasTestOnlyBuildTag(f) {
			return nil
		}
		pkgs[filepath.ToSlash(filepath.Dir(rel))] = true
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]string, 0, len(pkgs))
	for p := range pkgs {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// ExportedConstructors returns the exported constructor-shaped functions declared in
// one module-relative package directory.
func ExportedConstructors(root, importRelPath string) ([]Constructor, error) {
	dir := filepath.Join(root, filepath.FromSlash(importRelPath))
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	fset := token.NewFileSet()
	var out []Constructor
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		relFile := filepath.ToSlash(filepath.Join(importRelPath, e.Name()))
		if isTestOnlyFile(relFile) {
			continue
		}
		full := filepath.Join(root, filepath.FromSlash(relFile))
		f, err := parser.ParseFile(fset, full, nil, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("pcas intgate: parse %s: %w", relFile, err)
		}
		if fileHasTestOnlyBuildTag(f) {
			continue
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || !isConstructorName(fn.Name.Name) {
				continue
			}
			out = append(out, Constructor{Pkg: importRelPath, Name: fn.Name.Name, File: relFile})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].File < out[j].File
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// NonTestCallers returns the non-test references to c, excluding references inside c's
// own body (a recursive call is not a production caller).
func NonTestCallers(root string, c Constructor, searchRoots []string) ([]CallerRef, error) {
	idx, err := getCallIndex(root, searchRoots)
	if err != nil {
		return nil, err
	}
	key := modulePath + "/" + c.Pkg + "\x00" + c.Name
	span, hasSpan := idx.spansByKey[key]
	refs := idx.callsByKey[key]
	out := make([]CallerRef, 0, len(refs))
	for _, r := range refs {
		if hasSpan && r.File == span.File && r.Line >= span.StartLine && r.Line <= span.EndLine {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func getCallIndex(root string, searchRoots []string) (*callIndex, error) {
	key := root + "\x00" + strings.Join(searchRoots, "\x00")
	if idx := callIndexCache[key]; idx != nil {
		return idx, nil
	}
	idx := &callIndex{root: root, callsByKey: map[string][]CallerRef{}, spansByKey: map[string]funcSpan{}}
	for _, searchRoot := range searchRoots {
		absRoot := filepath.Join(root, filepath.FromSlash(searchRoot))
		if err := filepath.WalkDir(absRoot, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "node_modules", "dist", "testdata", "mock", "mocks", "fake", "fakes", "testkit":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(d.Name(), ".go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if isTestOnlyFile(rel) {
				return nil
			}
			return idx.indexFile(rel)
		}); err != nil {
			return nil, err
		}
	}
	callIndexCache[key] = idx
	return idx, nil
}

func (idx *callIndex) indexFile(rel string) error {
	full := filepath.Join(idx.root, filepath.FromSlash(rel))
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, full, nil, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("pcas intgate: parse %s: %w", rel, err)
	}
	if fileHasTestOnlyBuildTag(f) {
		return nil
	}
	pkgPath := pkgPathOfFile(rel)
	aliases := importAliasMap(f)
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil {
			continue
		}
		idx.spansByKey[modulePath+"/"+filepath.ToSlash(filepath.Dir(rel))+"\x00"+fn.Name.Name] = funcSpan{
			File:      rel,
			StartLine: fset.Position(fn.Pos()).Line,
			EndLine:   fset.Position(fn.End()).Line,
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		calleePkg, calleeName := resolveCallee(pkgPath, aliases, call.Fun)
		if calleePkg == "" || calleeName == "" {
			return true
		}
		idx.callsByKey[calleePkg+"\x00"+calleeName] = append(idx.callsByKey[calleePkg+"\x00"+calleeName], CallerRef{
			File: rel,
			Line: fset.Position(call.Lparen).Line,
		})
		return true
	})
	return nil
}

// SeamRootedResult is one constructor's seam verdict.
type SeamRootedResult struct {
	Constructor    Constructor
	SeamRooted     bool
	DirectFromSeam bool
}

// AssertSeamOnlyRoot computes, for every enumerated constructor, whether its non-test
// caller chain roots at a sanctioned seam file.
func AssertSeamOnlyRoot(root string) ([]SeamRootedResult, error) {
	ctors, err := LiveConstructors(root)
	if err != nil {
		return nil, err
	}
	ctorsInPkg := map[string][]Constructor{}
	for _, c := range ctors {
		ctorsInPkg[c.Pkg] = append(ctorsInPkg[c.Pkg], c)
	}
	seamAbs := map[string]bool{}
	for _, s := range SanctionedSeams {
		seamAbs[filepath.Join(root, filepath.FromSlash(s))] = true
	}

	const seamSentinel = "\x00SEAM"
	forward := map[string]map[string]bool{}
	direct := map[string]bool{}
	addEdge := func(from, to string) {
		if forward[from] == nil {
			forward[from] = map[string]bool{}
		}
		forward[from][to] = true
	}
	for _, c := range ctors {
		refs, err := NonTestCallers(root, c, defaultSearchRoots)
		if err != nil {
			return nil, err
		}
		to := ctorKey(c.Pkg, c.Name)
		for _, r := range refs {
			abs := filepath.Join(root, filepath.FromSlash(r.File))
			if seamAbs[abs] {
				addEdge(seamSentinel, to)
				direct[to] = true
				continue
			}
			callerPkg := filepath.ToSlash(filepath.Dir(r.File))
			for _, from := range ctorsInPkg[callerPkg] {
				addEdge(ctorKey(from.Pkg, from.Name), to)
			}
		}
	}

	reached := map[string]bool{}
	queue := []string{seamSentinel}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for nxt := range forward[cur] {
			if !reached[nxt] {
				reached[nxt] = true
				queue = append(queue, nxt)
			}
		}
	}
	var out []SeamRootedResult
	for _, c := range ctors {
		k := ctorKey(c.Pkg, c.Name)
		out = append(out, SeamRootedResult{Constructor: c, SeamRooted: reached[k], DirectFromSeam: direct[k]})
	}
	return out, nil
}

func isConstructorName(name string) bool {
	if name == "New" {
		return true
	}
	for _, pfx := range []string{"New", "Attach"} {
		if strings.HasPrefix(name, pfx) && len(name) > len(pfx) {
			r := rune(name[len(pfx)])
			return r >= 'A' && r <= 'Z'
		}
	}
	return false
}

// isTestOnlyFile also rejects generated *.pb.go: protobuf/gRPC stubs are machine-made
// plumbing, not delivered PCAS mechanisms, and the shell gate already excluded them.
func isTestOnlyFile(relPath string) bool {
	if strings.HasSuffix(relPath, "_test.go") || strings.HasSuffix(relPath, ".pb.go") {
		return true
	}
	for _, s := range strings.Split(filepath.ToSlash(relPath), "/") {
		switch s {
		case "mock", "mocks", "fake", "fakes", "testkit", "testdata":
			return true
		}
	}
	return false
}

var testOnlyBuildTags = []string{"testkit", "testonly", "test_only"}

func fileHasTestOnlyBuildTag(f *ast.File) bool {
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

func seamFileHasCoreExclusionTag(root, relFile string) (bool, error) {
	abs := filepath.Join(root, filepath.FromSlash(relFile))
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, abs, nil, parser.ParseComments)
	if err != nil {
		return false, err
	}
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			line := strings.TrimSpace(c.Text)
			if strings.HasPrefix(line, "//go:build") && strings.Contains(line, "!trstctl_core") {
				return true, nil
			}
		}
	}
	return false, nil
}

func verifySeamFilesExist(root string) error {
	for _, s := range SanctionedSeams {
		abs := filepath.Join(root, filepath.FromSlash(s))
		if _, err := os.Stat(abs); err != nil {
			return fmt.Errorf("sanctioned seam missing: %s (%v)", s, err)
		}
	}
	return nil
}

func resolveCallee(pkgPath string, aliases map[string]string, fun ast.Expr) (string, string) {
	switch x := fun.(type) {
	case *ast.Ident:
		return pkgPath, x.Name
	case *ast.SelectorExpr:
		id, ok := x.X.(*ast.Ident)
		if !ok {
			return "", ""
		}
		importPath := aliases[id.Name]
		if importPath == "" {
			return "", ""
		}
		return importPath, x.Sel.Name
	default:
		return "", ""
	}
}

func importAliasMap(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, imp := range f.Imports {
		if imp.Path == nil {
			continue
		}
		p := strings.Trim(imp.Path.Value, `"`)
		if p != modulePath && !hasPathPrefix(p, modulePath) {
			continue
		}
		local := ""
		if imp.Name != nil {
			local = imp.Name.Name
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

func pkgPathOfFile(relFile string) string {
	dir := filepath.ToSlash(filepath.Dir(relFile))
	if dir == "." || dir == "" {
		return modulePath
	}
	return modulePath + "/" + dir
}

func ctorKey(pkg, name string) string { return pkg + "\x00" + name }

func humanKey(k string) string {
	for i := 0; i < len(k); i++ {
		if k[i] == '\x00' {
			return k[:i] + "." + k[i+1:]
		}
	}
	return k
}

func lastPathSegment(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

func hasPathPrefix(p, prefix string) bool {
	return len(p) > len(prefix) && p[:len(prefix)] == prefix && p[len(prefix)] == '/'
}

func joinLines(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += "\n  - "
		}
		out += s
	}
	return out
}
