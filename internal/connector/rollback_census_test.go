// SPDX-License-Identifier: MPL-2.0

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

// The rollback census must match the code, in both directions (epic D4, C1a
// discipline).
//
// A capability list that drifts from the implementation is worse than no list.
// An operator reading "this connector can roll back" and finding it cannot,
// during an incident, is the specific failure the whole truth-integrity
// workstream exists to prevent — and the drift is silent, because nothing about
// a missing method fails to compile.
//
// So the census is checked against the source: every family that declares a
// Rollback method must be listed, and every family listed must declare one.
func TestRollbackCensusMatchesTheImplementations(t *testing.T) {
	t.Parallel()

	declared := familiesDeclaringRollback(t)
	listed := map[string]bool{}
	for _, name := range connector.RollbackCapableConnectors() {
		listed[name] = true
	}

	for name := range declared {
		if !listed[name] {
			t.Errorf("connector %q implements Rollback but is not in the rollback census; "+
				"an operator cannot discover a capability that is not advertised", name)
		}
	}
	for name := range listed {
		if !declared[name] {
			t.Errorf("the rollback census claims %q can roll back, but its package declares no "+
				"Rollback method; this is the drift that leaves an operator holding a "+
				"capability list the binary does not honour", name)
		}
	}
}

// The census is sorted and free of duplicates, so the served capability list is
// stable rather than depending on declaration order.
func TestRollbackCensusIsStable(t *testing.T) {
	t.Parallel()
	got := connector.RollbackCapableConnectors()
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
	if len(got) == 0 {
		t.Error("the census is empty; D4 shipped rollback for at least one family")
	}
}

// familiesDeclaringRollback parses each connector package and reports which
// declare a method named Rollback on *Connector.
func familiesDeclaringRollback(t *testing.T) map[string]bool {
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
				if !ok || fn.Recv == nil || fn.Name.Name != "Rollback" {
					continue
				}
				out[family] = true
			}
		}
	}
	return out
}

// The object name is derived from the fingerprint, and that derivation is what
// every rollback depends on. If a deploy and a rollback ever computed different
// names, every rollback would report "predecessor not installed" for objects
// that are sitting right there.
func TestDeployAndRollbackAgreeOnObjectNames(t *testing.T) {
	t.Parallel()
	const base = "clientssl_app"
	const fp = "AB12CD34EF567890abcdef1234567890abcdef1234567890abcdef1234567890"

	deployed := connector.DeployedObjectName(base, fp)
	rolled := connector.RollbackObjectName(base, fp)
	if deployed != rolled {
		t.Fatalf("deploy names %q, rollback looks for %q", deployed, rolled)
	}
	if !strings.HasPrefix(deployed, base+"-") {
		t.Errorf("object name %q does not keep the base %q, so an operator cannot tell "+
			"which target it belongs to when they look at the appliance", deployed, base)
	}
	// Case and the sha256: prefix must not change the name. A fingerprint that
	// arrives uppercase from one path and lowercase from another would name two
	// different objects for one certificate.
	if lower := connector.DeployedObjectName(base, "sha256:"+strings.ToLower(fp)); lower != deployed {
		t.Errorf("fingerprint formatting changes the object name: %q vs %q", lower, deployed)
	}

	// Two different certificates must not collide, or a deploy would overwrite
	// the predecessor it is supposed to leave standing.
	other := connector.DeployedObjectName(base, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if other == deployed {
		t.Error("two different fingerprints produced the same object name")
	}

	// No fingerprint means the pre-D4 name, unchanged: a connector with nothing
	// to hash should deploy the way it always did rather than invent a name.
	if plain := connector.DeployedObjectName(base, ""); plain != base {
		t.Errorf("empty fingerprint produced %q, want the bare base %q", plain, base)
	}
}
