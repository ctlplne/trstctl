package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const controlPlaneHotspotMaxLines = 140

// TestControlPlaneStartupHotspotsStaySplit is the CODE-001 guardrail: the
// control-plane boot, server assembly, and config validation paths must remain
// decomposed into named stages instead of drifting back into one huge function.
func TestControlPlaneStartupHotspotsStaySplit(t *testing.T) {
	root := moduleRoot(t)
	var findings []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if skipGoWalkEntry(d) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel := slashRel(t, root, path)
		if !isControlPlaneStartupPath(rel) || isGeneratedGo(t, path) {
			return nil
		}
		for _, fn := range parseFunctionLengths(t, path) {
			if fn.lines > controlPlaneHotspotMaxLines {
				findings = append(findings, fmt.Sprintf("%s:%d %s spans %d lines (limit %d)", rel, fn.line, fn.name, fn.lines, controlPlaneHotspotMaxLines))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	if len(findings) > 0 {
		sort.Strings(findings)
		t.Fatalf("control-plane startup hotspots regressed; split these functions into named stages:\n%s", strings.Join(findings, "\n"))
	}
}

type functionLength struct {
	name  string
	line  int
	lines int
}

func parseFunctionLengths(t *testing.T, path string) []functionLength {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var lengths []functionLength
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		start := fset.Position(fn.Pos()).Line
		end := fset.Position(fn.End()).Line
		lengths = append(lengths, functionLength{
			name:  functionDisplayName(fn),
			line:  start,
			lines: end - start + 1,
		})
	}
	return lengths
}

func functionDisplayName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	return "(receiver)." + fn.Name.Name
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod")
		}
		dir = parent
	}
}

func slashRel(t *testing.T, root, path string) string {
	t.Helper()
	rel, err := filepath.Rel(root, path)
	if err != nil {
		t.Fatalf("rel %s to %s: %v", path, root, err)
	}
	return filepath.ToSlash(rel)
}

func skipGoWalkEntry(d os.DirEntry) bool {
	name := d.Name()
	if d.IsDir() {
		switch name {
		case ".git", "bin", "dist", "node_modules", "testdata", "vendor":
			return true
		}
		return false
	}
	return strings.HasSuffix(name, "_test.go") || !strings.HasSuffix(name, ".go")
}

func isControlPlaneStartupPath(rel string) bool {
	for _, prefix := range []string{
		"cmd/trstctl/",
		"internal/config/",
		"internal/server/",
	} {
		if strings.HasPrefix(rel, prefix) {
			return true
		}
	}
	return false
}

func isGeneratedGo(t *testing.T, path string) bool {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(src) > 2048 {
		src = src[:2048]
	}
	head := string(src)
	return strings.Contains(head, "Code generated") && strings.Contains(head, "DO NOT EDIT")
}
