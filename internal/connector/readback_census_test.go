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

// The readback census must match the code, in both directions, like the
// rollback census (epic E2).
//
// The relay asks a family's device what it has installed only when the census
// says the family can be asked, and it reports a connector that turns out not
// to implement Readback as "the appliance did not answer". So a family listed
// without the method is not merely unverified: every relay deploy to it tells
// the operator the appliance was unreachable when nothing asked it anything,
// and the readback gate counts toward the family's migrated status.
func TestReadbackCensusMatchesTheImplementations(t *testing.T) {
	t.Parallel()

	declared := familiesDeclaringReadback(t)
	listed := map[string]bool{}
	for _, name := range connector.ReadbackCapableConnectors() {
		listed[name] = true
	}
	for name := range declared {
		if !listed[name] {
			t.Errorf("connector %q implements Readback but is not in the readback census; "+
				"the relay will never ask its device what is installed", name)
		}
	}
	for name := range listed {
		if !declared[name] {
			t.Errorf("the readback census claims %q can report what is installed, but its package "+
				"declares no Readback method; every relay deploy to it reports an unreachable "+
				"appliance that nothing asked", name)
		}
	}
}

// The census is sorted and free of duplicates, so the served capability list
// is stable.
func TestReadbackCensusIsStable(t *testing.T) {
	t.Parallel()
	got := connector.ReadbackCapableConnectors()
	if !sort.StringsAreSorted(got) {
		t.Errorf("census is not sorted: %v", got)
	}
	seen := map[string]bool{}
	for _, name := range got {
		if seen[name] {
			t.Errorf("census lists %q twice", name)
		}
		seen[name] = true
	}
}

// familiesDeclaringReadback parses each connector package and reports which
// declare a method named Readback.
func familiesDeclaringReadback(t *testing.T) map[string]bool {
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
		files, err := filepath.Glob(filepath.Join(entry.Name(), "*.go"))
		if err != nil {
			t.Fatalf("glob %s: %v", entry.Name(), err)
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
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil && fn.Name.Name == "Readback" {
					out[familyForPackageDir(entry.Name())] = true
				}
			}
		}
	}
	return out
}
