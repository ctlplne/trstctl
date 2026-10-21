// SPDX-License-Identifier: BUSL-1.1

package connector_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
)

// The takedown census must match the code in both directions (A43), for the
// same reason the rollback census does: a capability list that drifts from the
// implementation misleads an operator during an incident.
func TestTakedownCensusMatchesTheImplementations(t *testing.T) {
	t.Parallel()
	declared := familiesDeclaringMethod(t, "Takedown")
	listed := map[string]bool{}
	for _, name := range connector.TakedownCapableConnectors() {
		listed[name] = true
	}
	for name := range declared {
		if !listed[name] {
			t.Errorf("connector %q implements Takedown but is not in the takedown census", name)
		}
	}
	for name := range listed {
		if !declared[name] {
			t.Errorf("the takedown census claims %q can remove objects, but its package declares no Takedown method", name)
		}
	}
	got := connector.TakedownCapableConnectors()
	if !sort.StringsAreSorted(got) || len(got) == 0 {
		t.Errorf("takedown census must be sorted and non-empty: %v", got)
	}
	for _, name := range got {
		if !connector.CanRollback(name) {
			t.Errorf("%q can take down objects but not re-bind; takedown of a bound object would have no safe first step", name)
		}
	}
}

// familiesDeclaringMethod parses each connector package and reports which
// declare a method of that name on a receiver.
func familiesDeclaringMethod(t *testing.T, method string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read connector dir: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		family := entry.Name()
		files, err := filepath.Glob(filepath.Join(family, "*.go"))
		if err != nil {
			t.Fatalf("glob %s: %v", family, err)
		}
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
			if err != nil {
				continue
			}
			for _, decl := range parsed.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || fn.Name.Name != method {
					continue
				}
				out[family] = true
			}
		}
	}
	return out
}
