// SPDX-License-Identifier: BUSL-1.1

package events_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Every new event-log constructor or direct JetStream write needs an ingress
// review. Count actual call expressions, not text matches in comments.
func TestEventWriteSourceCensus(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	allowedEventsCalls := map[string]map[string]int{
		"internal/eventstest/fixture.go": {"Open": 1, "WithFixtureAppendAdmission": 1},
		// Live performance work writes real sealed secrets. It uses required
		// store-backed custody admission, never the permissive fixture source.
		"internal/perf/live.go":              {"Open": 1, "WithRequiredAppendAdmission": 1},
		"internal/server/history_rewrite.go": {"Open": 1},
		"internal/server/event_protection_source.go": {"WithAppendAdmission": 2,
			"WithBackupHistoryAdmission": 1, "WithBackupHistoryJournal": 1,
			"WithRequiredAppendAdmission":        1,
			"WithRequiredBackupHistoryAdmission": 1,
			"WithIngressWireStage":               1,
			"WithIngressCanonicalProof":          1},
		// The offline provider grant producer must authenticate its own append;
		// it does not run through the serving source above.
		"ee/provider/grantcmd.go": {"WithRequiredAppendAdmission": 1, "WithAppendAdmission": 1},
	}
	allowedDirectWrites := map[string]map[string]int{
		"internal/events/event_id_index.go":      {"Publish": 3},
		"internal/events/tenant_data_rewrite.go": {"Publish": 4, "SecureDeleteMsg": 3},
		"internal/events/backup_history.go":      {"Publish": 1, "PublishMsg": 1, "SecureDeleteMsg": 2},
		"internal/events/tenant_index.go":        {"Publish": 2},
		"internal/events/events.go":              {"SecureDeleteMsg": 1},
	}
	seenEvents := map[string]map[string]int{}
	seenDirect := map[string]map[string]int{}
	for _, dir := range []string{"internal", "cmd", "ee"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			eventsAlias := ""
			for _, spec := range file.Imports {
				name, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					return err
				}
				if name != "trstctl.com/trstctl/internal/events" {
					continue
				}
				eventsAlias = "events"
				if spec.Name != nil {
					eventsAlias = spec.Name.Name
				}
				if eventsAlias == "." || eventsAlias == "_" {
					t.Errorf("%s hides the event-log constructor behind an import alias", rel)
				}
			}
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == eventsAlias && eventsAlias != "" {
					switch sel.Sel.Name {
					case "Open", "WithFixtureAppendAdmission", "WithAppendAdmission",
						"WithIngressWireStage", "WithIngressCanonicalProof",
						"WithBackupHistoryAdmission", "WithBackupHistoryJournal", "WithRequiredAppendAdmission",
						"WithRequiredBackupHistoryAdmission":
						countSourceCall(seenEvents, rel, sel.Sel.Name)
					}
				}
				if strings.HasPrefix(rel, "internal/events/") {
					switch sel.Sel.Name {
					case "Publish", "PublishMsg", "SecureDeleteMsg":
						countSourceCall(seenDirect, rel, sel.Sel.Name)
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	compareSourceCalls(t, "event constructor/admission", seenEvents, allowedEventsCalls)
	compareSourceCalls(t, "direct broker write", seenDirect, allowedDirectWrites)
}

func countSourceCall(counts map[string]map[string]int, path, name string) {
	if counts[path] == nil {
		counts[path] = map[string]int{}
	}
	counts[path][name]++
}

func compareSourceCalls(t *testing.T, label string, got, want map[string]map[string]int) {
	t.Helper()
	for path, calls := range got {
		for name, count := range calls {
			if count != want[path][name] {
				t.Errorf("%s %s %s calls=%d, reviewed=%d", label, path, name, count, want[path][name])
			}
		}
	}
	for path, calls := range want {
		for name, count := range calls {
			if got[path][name] != count {
				t.Errorf("%s %s %s calls=%d, reviewed=%d", label, path, name, got[path][name], count)
			}
		}
	}
}
