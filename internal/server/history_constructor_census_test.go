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
		"internal/eventstest/fixture.go":     true, // explicit test-only fixture adapter
		"internal/server/history_rewrite.go": true, // central production constructor
	}
	found := make(map[string]bool)
	allowedFixture := map[string]int{
		"internal/perf/live.go":                      1,
		"scripts/perf/cmd/capacitycalibrate/main.go": 1,
		"scripts/perf/cmd/soakcapture/main.go":       1,
		"scripts/perf/cmd/spineburst/main.go":        2,
	}
	fixtureFound := make(map[string]int)
	fixtureOptionFound := make(map[string]int)
	productionOptionFound := make(map[string]int)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && entry.Name() != "." && len(entry.Name()) > 0 && entry.Name()[0] == '.' {
				return filepath.SkipDir
			}
			switch entry.Name() {
			case ".git", "private", "vendor", "node_modules", "dist":
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
		fixtureAlias := ""
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			switch importPath {
			case "trstctl.com/trstctl/internal/events":
				alias = "events"
				if spec.Name != nil {
					alias = spec.Name.Name
				}
			case "trstctl.com/trstctl/internal/eventstest":
				fixtureAlias = "eventstest"
				if spec.Name != nil {
					fixtureAlias = spec.Name.Name
				}
			}
		}
		if alias == "" && fixtureAlias == "" {
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
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if pkg.Name == alias {
				switch selector.Sel.Name {
				case "Open":
					found[rel] = true
				case "WithFixtureAppendAdmission":
					fixtureOptionFound[rel]++
				case "WithRequiredAppendAdmission", "WithAppendAdmission",
					"WithRequiredBackupHistoryAdmission", "WithBackupHistoryAdmission":
					productionOptionFound[rel+":"+selector.Sel.Name]++
				}
			}
			if pkg.Name == fixtureAlias && selector.Sel.Name == "OpenFixture" {
				fixtureFound[rel]++
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
	for path, count := range fixtureFound {
		if count != allowedFixture[path] {
			t.Errorf("production %s calls test-only OpenFixture %d times; reviewed count is %d", path, count, allowedFixture[path])
		}
	}
	for path, count := range allowedFixture {
		if fixtureFound[path] != count {
			t.Errorf("fixture census allowlist entry %s saw %d calls, want %d", path, fixtureFound[path], count)
		}
	}
	if len(fixtureOptionFound) != 1 || fixtureOptionFound["internal/eventstest/fixture.go"] != 1 {
		t.Errorf("test-only fixture admission options moved outside the explicit fixture helper: %v", fixtureOptionFound)
	}
	// The serving source has two distinct append ingress paths: ordinary
	// mutations and restored wire history. The offline provider command has
	// its own required admission, so neither path can silently lose custody.
	expectedProductionOptions := map[string]int{
		"internal/server/event_protection_source.go:WithRequiredAppendAdmission":        1,
		"internal/server/event_protection_source.go:WithAppendAdmission":                2,
		"internal/server/event_protection_source.go:WithRequiredBackupHistoryAdmission": 1,
		"internal/server/event_protection_source.go:WithBackupHistoryAdmission":         1,
		"ee/provider/grantcmd.go:WithRequiredAppendAdmission":                           1,
		"ee/provider/grantcmd.go:WithAppendAdmission":                                   1,
	}
	if len(productionOptionFound) != len(expectedProductionOptions) {
		t.Errorf("configured production source lost its event or raw-history admission adapter: %v", productionOptionFound)
	}
	for option, want := range expectedProductionOptions {
		if productionOptionFound[option] != want {
			t.Errorf("production admission %s called %d times, want %d", option, productionOptionFound[option], want)
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
