// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestProductionEventLogConstructorsCannotBypassHistorySafety(t *testing.T) {
	t.Parallel()
	root := filepath.Clean(filepath.Join("..", ".."))
	allowed := map[string]bool{
		"internal/perf/live.go":                      true, // isolated benchmark/evaluation harness
		"internal/server/history_rewrite.go":         true, // central production constructor
		"scripts/perf/cmd/capacitycalibrate/main.go": true, // benchmark command
		"scripts/perf/cmd/soakcapture/main.go":       true, // benchmark command
		"scripts/perf/cmd/spineburst/main.go":        true, // benchmark command
	}
	found := make(map[string]bool)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && entry.Name() != "." && len(entry.Name()) > 0 && entry.Name()[0] == '.' {
				return filepath.SkipDir
			}
			switch entry.Name() {
			case ".git", "vendor", "node_modules", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || filepath.Base(path) == "" || len(path) >= len("_test.go") && path[len(path)-len("_test.go"):] == "_test.go" {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		alias := ""
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if importPath != "trstctl.com/trstctl/internal/events" {
				continue
			}
			alias = "events"
			if spec.Name != nil {
				alias = spec.Name.Name
			}
		}
		if alias == "" {
			return nil
		}
		file, err = parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Open" {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if ok && pkg.Name == alias {
				found[rel] = true
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for path := range found {
		if !allowed[path] {
			t.Errorf("production %s calls events.Open directly; use a history-safe constructor", path)
		}
	}
	for path := range allowed {
		if !found[path] {
			t.Errorf("constructor census allowlist entry %s is stale", path)
		}
	}
	providerSource, err := os.ReadFile(filepath.Join(root, "ee", "provider", "grantcmd.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(providerSource), "events.OpenRequiringSanitizedSchedulerHistory(") {
		t.Fatal("provider grant command no longer uses the fail-closed scheduler-history constructor")
	}
}
