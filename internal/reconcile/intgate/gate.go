// SPDX-License-Identifier: BUSL-1.1

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

const modulePath = "trstctl.com/trstctl"

// InScopePackages are the XREC packages. ee/federation (the licensed HA import
// worker, attached from the tagged ee/ seam) was listed here while XREC was
// itself an ee/ feature; it is not part of the family and left the list when
// XREC moved into the core on 2026-09-20.
var InScopePackages = []string{
	"internal/reconcile",
	"internal/reconcile/canon",
	"internal/reconcile/canon/reducers",
	"internal/reconcile/canon/reducers/kmip",
	"internal/reconcile/digest",
	"internal/reconcile/witness",
	"internal/reconcile/plan",
	"internal/reconcile/plan/remediation",
	"internal/reconcile/verify",
	"internal/reconcile/rounds",
	"internal/reconcile/quarantine",
}

var SanctionedSeams = []string{
	"cmd/trstctl/attach_families.go",
	"cmd/trstctl-signer/attach_families.go",
}

var defaultSearchRoots = []string{"cmd", "internal", "ee"}

type Constructor struct {
	Pkg  string
	Name string
	File string
}

func (c Constructor) Qualified() string {
	return lastPathSegment(c.Pkg) + "." + c.Name
}

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
			return "", fmt.Errorf("xrec intgate: go.mod not found walking up from %s", start)
		}
		dir = parent
	}
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

func isTestOnlyFile(relPath string) bool {
	if strings.HasSuffix(relPath, "_test.go") {
		return true
	}
	segs := strings.Split(filepath.ToSlash(relPath), "/")
	for _, s := range segs {
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
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		relFile := filepath.ToSlash(filepath.Join(importRelPath, e.Name()))
		full := filepath.Join(root, filepath.FromSlash(relFile))
		f, err := parser.ParseFile(fset, full, nil, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("xrec intgate: parse %s: %w", relFile, err)
		}
		if fileHasTestOnlyBuildTag(f) {
			continue
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || !isConstructorName(fn.Name.Name) {
				continue
			}
			out = append(out, Constructor{
				Pkg:  importRelPath,
				Name: fn.Name.Name,
				File: relFile,
			})
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

func LiveConstructors(root string) ([]Constructor, error) {
	var out []Constructor
	seen := map[string]bool{}
	for _, pkg := range InScopePackages {
		ctors, err := ExportedConstructors(root, pkg)
		if err != nil {
			return nil, err
		}
		for _, c := range ctors {
			key := ctorKey(c.Pkg, c.Name)
			if seen[key] {
				return nil, fmt.Errorf("duplicate constructor key %s", humanKey(key))
			}
			seen[key] = true
			out = append(out, c)
		}
	}
	return out, nil
}

func NonTestCallers(root string, c Constructor, searchRoots []string) ([]CallerRef, error) {
	idx, err := getCallIndex(root, searchRoots)
	if err != nil {
		return nil, err
	}
	key := modulePath + "/" + c.Pkg + "\x00" + c.Name
	refs := append([]CallerRef(nil), idx.callsByKey[key]...)
	span, hasSpan := idx.spansByKey[key]
	out := refs[:0]
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
	idx := &callIndex{
		root:       root,
		callsByKey: map[string][]CallerRef{},
		spansByKey: map[string]funcSpan{},
	}
	for _, searchRoot := range searchRoots {
		absRoot := filepath.Join(root, filepath.FromSlash(searchRoot))
		if err := filepath.WalkDir(absRoot, func(path string, d os.DirEntry, err error) error {
			if err != nil {
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
		return fmt.Errorf("xrec intgate: parse %s: %w", rel, err)
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
		fnKey := modulePath + "/" + filepath.ToSlash(filepath.Dir(rel)) + "\x00" + fn.Name.Name
		idx.spansByKey[fnKey] = funcSpan{
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
		out = append(out, SeamRootedResult{
			Constructor: c,
			SeamRooted:  reached[k],
		})
	}
	return out, nil
}

type SeamRootedResult struct {
	Constructor Constructor
	SeamRooted  bool
}

// seamFileIsAlwaysLinked reports whether the seam carries no build constraint
// on trstctl_core in either direction: the core families attach in every build.
func seamFileIsAlwaysLinked(root, relFile string) (bool, error) {
	abs := filepath.Join(root, filepath.FromSlash(relFile))
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, abs, nil, parser.ParseComments)
	if err != nil {
		return false, err
	}
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			line := strings.TrimSpace(c.Text)
			if strings.HasPrefix(line, "//go:build") && strings.Contains(line, "trstctl_core") {
				return false, nil
			}
		}
	}
	return true, nil
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
