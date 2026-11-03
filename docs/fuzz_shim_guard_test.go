// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ClusterFuzzLite builds every native fuzz target with a testing shim whose
// *testing.F implements only part of testing.TB (Go 1.26 added ArtifactDir,
// which the shim lacks). A fuzz target that hands its f to a helper declared
// with a testing.TB parameter compiles under go test and fails only in that
// build (CI 41508856233: internal/agent/sshkrl FuzzParseRevocations). Seed
// helpers take a narrow interface of the methods they use instead.
func TestFuzzTargetsDoNotHandFToTestingTBHelpers(t *testing.T) {
	helper := regexp.MustCompile(`func (\w+)\(\w+ testing\.TB\b`)
	target := regexp.MustCompile(`func (Fuzz\w+)\((\w+) \*testing\.F\)\s*\{`)
	byDir := map[string][]string{}
	for _, root := range []string{"../internal", "../ee", "../cmd", "../tools"} {
		_ = filepath.WalkDir(filepath.FromSlash(root), func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(path, "_test.go") {
				byDir[filepath.Dir(path)] = append(byDir[filepath.Dir(path)], path)
			}
			return nil
		})
	}
	var findings []string
	for _, files := range byDir {
		sources := map[string]string{}
		helpers := map[string]bool{}
		for _, path := range files {
			body := read(t, filepath.ToSlash(path))
			sources[path] = body
			for _, m := range helper.FindAllStringSubmatch(body, -1) {
				helpers[m[1]] = true
			}
		}
		if len(helpers) == 0 {
			continue
		}
		for path, src := range sources {
			for _, m := range target.FindAllStringSubmatchIndex(src, -1) {
				name, f := src[m[2]:m[3]], src[m[4]:m[5]]
				seeds := src[m[1]:]
				if end := strings.Index(seeds, f+".Fuzz("); end >= 0 {
					seeds = seeds[:end]
				}
				for h := range helpers {
					if regexp.MustCompile(`\b` + regexp.QuoteMeta(h) + `\(\s*` + regexp.QuoteMeta(f) + `\b`).MatchString(seeds) {
						findings = append(findings, filepath.ToSlash(path)+": "+name+" passes "+f+" to "+h+"(testing.TB)")
					}
				}
			}
		}
	}
	sort.Strings(findings)
	if len(findings) > 0 {
		t.Fatalf("fuzz targets hand *testing.F to testing.TB helpers (ClusterFuzzLite cannot compile them):\n%s", strings.Join(findings, "\n"))
	}
}

// ClusterFuzzLite runs each fuzz binary away from the source tree, and its
// shim's f.Fatal returns instead of stopping (owner note 2026-11-02, item 3:
// internal/crypto/tlsprobe FuzzNativeProbeOutput read its seed from
// ../certinfo/testdata by relative path, the read failed, Fatal returned, and
// the target crashed on a nil *pem.Block before its first input). A fuzz
// target's setup (everything before f.Fuzz) therefore reads no files — seeds
// are compiled in with go:embed or literals — and every setup Fatal or FailNow
// inside a block is followed by return.
func TestFuzzTargetSetupReadsNoFilesAndStopsAfterFatal(t *testing.T) {
	fileReads := map[string]bool{"os.ReadFile": true, "os.Open": true, "os.OpenFile": true, "os.OpenRoot": true,
		"os.ReadDir": true, "filepath.Glob": true, "filepath.WalkDir": true, "filepath.Walk": true, "ioutil.ReadFile": true}
	var findings []string
	fset := token.NewFileSet()
	byDir := map[string][]*ast.File{}
	for _, root := range []string{"../internal", "../ee", "../cmd", "../tools"} {
		_ = filepath.WalkDir(filepath.FromSlash(root), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, perr := parser.ParseFile(fset, path, read(t, filepath.ToSlash(path)), 0)
			if perr == nil {
				byDir[filepath.Dir(path)] = append(byDir[filepath.Dir(path)], file)
			}
			return nil
		})
	}
	callName := func(call *ast.CallExpr) string {
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			if id, ok := fn.X.(*ast.Ident); ok {
				return id.Name + "." + fn.Sel.Name
			}
		case *ast.Ident:
			return fn.Name
		}
		return ""
	}
	readsFiles := func(body ast.Node) bool {
		found := false
		ast.Inspect(body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && fileReads[callName(call)] {
				found = true
			}
			return !found
		})
		return found
	}
	for _, files := range byDir {
		// Same-package helpers that read files count as reads (one level).
		readers := map[string]bool{}
		for _, file := range files {
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Body != nil && readsFiles(fn.Body) {
					readers[fn.Name.Name] = true
				}
			}
		}
		for _, file := range files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || !strings.HasPrefix(fn.Name.Name, "Fuzz") || fn.Body == nil || len(fn.Type.Params.List) != 1 || len(fn.Type.Params.List[0].Names) != 1 {
					continue
				}
				star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
				if !ok {
					continue
				}
				if sel, ok := star.X.(*ast.SelectorExpr); !ok || sel.Sel.Name != "F" {
					continue
				}
				f := fn.Type.Params.List[0].Names[0].Name
				where := fset.Position(fn.Pos())
				isCallOn := func(st ast.Stmt, names ...string) bool {
					es, ok := st.(*ast.ExprStmt)
					if !ok {
						return false
					}
					call, ok := es.X.(*ast.CallExpr)
					if !ok {
						return false
					}
					for _, name := range names {
						if callName(call) == f+"."+name {
							return true
						}
					}
					return false
				}
				var walk func(stmts []ast.Stmt, nested bool) bool
				walk = func(stmts []ast.Stmt, nested bool) bool {
					for i, st := range stmts {
						if isCallOn(st, "Fuzz") {
							return true
						}
						ast.Inspect(st, func(n ast.Node) bool {
							if _, lit := n.(*ast.FuncLit); lit {
								return false
							}
							if call, ok := n.(*ast.CallExpr); ok && (fileReads[callName(call)] || readers[callName(call)]) {
								findings = append(findings, where.String()+" "+fn.Name.Name+": setup reads a file ("+callName(call)+")")
							}
							return true
						})
						if isCallOn(st, "Fatal", "Fatalf", "FailNow") && nested && (i+1 >= len(stmts)) {
							findings = append(findings, fset.Position(st.Pos()).String()+" "+fn.Name.Name+": setup "+f+".Fatal is not followed by return")
						} else if isCallOn(st, "Fatal", "Fatalf", "FailNow") && i+1 < len(stmts) {
							if _, ret := stmts[i+1].(*ast.ReturnStmt); !ret {
								findings = append(findings, fset.Position(st.Pos()).String()+" "+fn.Name.Name+": setup "+f+".Fatal is not followed by return")
							}
						}
						var stop bool
						switch s := st.(type) {
						case *ast.IfStmt:
							stop = walk(s.Body.List, true)
							if blk, ok := s.Else.(*ast.BlockStmt); ok && !stop {
								stop = walk(blk.List, true)
							} else if elif, ok := s.Else.(*ast.IfStmt); ok && !stop {
								stop = walk([]ast.Stmt{elif}, true)
							}
						case *ast.ForStmt:
							stop = walk(s.Body.List, true)
						case *ast.RangeStmt:
							stop = walk(s.Body.List, true)
						case *ast.BlockStmt:
							stop = walk(s.List, true)
						}
						if stop {
							return true
						}
					}
					return false
				}
				walk(fn.Body.List, false)
			}
		}
	}
	sort.Strings(findings)
	if len(findings) > 0 {
		t.Fatalf("fuzz target setup the ClusterFuzzLite runner cannot run:\n%s", strings.Join(findings, "\n"))
	}
}

// ClusterFuzzLite's testing shim implements testing.F and testing.T only in
// part (CI 41558210954, the first run whose fuzzers all built): Context()
// panics on both, the fuzz body's t.Cleanup runs its function at once (so
// t.Cleanup(key.Destroy) destroyed internal/crypto/mtls's CA key before the
// target used it), and t.Deadline, Failed, Parallel, Run and Skipped panic.
// A fuzz target's setup therefore never asks f (or a same-package helper it
// hands f to) for Context, and its fuzz body never asks t (or a helper it
// hands t to) for any of those; it uses context.Background and defer.
func TestFuzzTargetsCallOnlyWhatTheFuzzShimRuns(t *testing.T) {
	setupForbidden := map[string]bool{"Context": true}
	bodyForbidden := map[string]bool{"Context": true, "Cleanup": true, "Deadline": true, "Failed": true, "Parallel": true, "Run": true, "Skipped": true}
	var findings []string
	fset := token.NewFileSet()
	byDir := map[string][]*ast.File{}
	for _, root := range []string{"../internal", "../ee", "../cmd", "../tools"} {
		_ = filepath.WalkDir(filepath.FromSlash(root), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, perr := parser.ParseFile(fset, path, read(t, filepath.ToSlash(path)), 0)
			if perr == nil {
				byDir[filepath.Dir(path)] = append(byDir[filepath.Dir(path)], file)
			}
			return nil
		})
	}
	// calls reports each method called on the variable named recv in body,
	// skipping nothing: a closure that captures it still runs under the shim.
	calls := func(body ast.Node, recv string, forbidden map[string]bool, report func(method string, at token.Pos)) {
		ast.Inspect(body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == recv && forbidden[sel.Sel.Name] {
					report(sel.Sel.Name, call.Pos())
				}
			}
			return true
		})
	}
	for _, files := range byDir {
		helpers := map[string]*ast.FuncDecl{}
		for _, file := range files {
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Body != nil {
					helpers[fn.Name.Name] = fn
				}
			}
		}
		// check reports forbidden calls on recv in body and, one level down, in
		// each same-package helper body receives recv as an argument.
		check := func(target string, body ast.Node, recv string, forbidden map[string]bool, what string) {
			calls(body, recv, forbidden, func(method string, at token.Pos) {
				findings = append(findings, fmt.Sprintf("%s %s: %s calls %s.%s", fset.Position(at), target, what, recv, method))
			})
			ast.Inspect(body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				id, ok := call.Fun.(*ast.Ident)
				if !ok || helpers[id.Name] == nil {
					return true
				}
				helper := helpers[id.Name]
				var params []string
				for _, field := range helper.Type.Params.List {
					for _, name := range field.Names {
						params = append(params, name.Name)
					}
				}
				for i, arg := range call.Args {
					if a, ok := arg.(*ast.Ident); ok && a.Name == recv && i < len(params) {
						calls(helper.Body, params[i], forbidden, func(method string, at token.Pos) {
							findings = append(findings, fmt.Sprintf("%s %s: %s hands %s to %s, which calls %s.%s", fset.Position(at), target, what, recv, id.Name, params[i], method))
						})
					}
				}
				return true
			})
		}
		for _, file := range files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || !strings.HasPrefix(fn.Name.Name, "Fuzz") || fn.Body == nil || len(fn.Type.Params.List) != 1 || len(fn.Type.Params.List[0].Names) != 1 {
					continue
				}
				star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
				if !ok {
					continue
				}
				if sel, ok := star.X.(*ast.SelectorExpr); !ok || sel.Sel.Name != "F" {
					continue
				}
				f := fn.Type.Params.List[0].Names[0].Name
				check(fn.Name.Name, fn.Body, f, setupForbidden, "setup")
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Fuzz" || len(call.Args) != 1 {
						return true
					}
					if id, ok := sel.X.(*ast.Ident); !ok || id.Name != f {
						return true
					}
					lit, ok := call.Args[0].(*ast.FuncLit)
					if !ok || len(lit.Type.Params.List) == 0 || len(lit.Type.Params.List[0].Names) == 0 {
						return true
					}
					check(fn.Name.Name, lit.Body, lit.Type.Params.List[0].Names[0].Name, bodyForbidden, "the fuzz body")
					return false
				})
			}
		}
	}
	sort.Strings(findings)
	if len(findings) > 0 {
		t.Fatalf("fuzz targets call what the ClusterFuzzLite shim does not run:\n%s", strings.Join(findings, "\n"))
	}
}
