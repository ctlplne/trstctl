// SPDX-License-Identifier: MPL-2.0

package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEveryPublicRouteHasAbuseControl is the regression guard for the
// unauthenticated brute-force surface.
//
// A route with perm == "" is public: no credential has been checked when the
// handler runs, so the handler itself is the only thing standing between an
// attacker and unlimited guessing. Six such routes in auth.go call
// allowSpecialRouteRequest first; machineLogin — an unauthenticated credential
// exchange, the most brute-forceable shape there is — did not. That is the kind
// of gap nobody notices until someone lists the public routes, which is exactly
// what this test does.
func TestEveryPublicRouteHasAbuseControl(t *testing.T) {
	a := &API{}
	handlerNames := handlerFuncNames(t)

	// Exempt by decision, not by omission. A public route earns an exemption only
	// when there is nothing to guess AND nothing expensive to drive.
	exempt := map[string]string{
		"getBrand": "resolves login-page branding from the Host header out of memory: no " +
			"caller-supplied identifier to enumerate, no secret to guess, and no work to " +
			"amplify. Rate-limiting the pre-login branding fetch would risk breaking the " +
			"login page for everyone behind one NAT in exchange for nothing.",
	}

	var public, unguarded []string
	for _, r := range a.routes() {
		if r.perm != "" || r.opID == "" {
			continue
		}
		public = append(public, r.opID)
		if _, ok := exempt[r.opID]; ok {
			continue
		}
		// Operation ids equal handler method names by convention across this
		// package (opID "machineLogin" -> a.machineLogin), so the id indexes
		// the handler-source map directly (AUD-201 follow-up L1/V30: the
		// former handlerNameForOpID wrapper was an identity function whose
		// *testing.T implied a mapping that could fail; none exists).
		body, ok := handlerNames[r.opID]
		if !ok {
			// The handler could not be located by name; skip rather than fail, so
			// this guard never blocks on a naming convention it does not control.
			continue
		}
		if !strings.Contains(body, "allowSpecialRouteRequest") {
			unguarded = append(unguarded, r.opID)
		}
	}

	if len(public) == 0 {
		t.Fatal("no public routes found; this guard is not testing anything")
	}
	sort.Strings(unguarded)
	if len(unguarded) > 0 {
		t.Errorf("public (unauthenticated) routes with no abuse control: %v\n"+
			"each must call allowSpecialRouteRequest before doing work, or an attacker can "+
			"guess against it as fast as the network allows", unguarded)
	}
	t.Logf("checked %d public routes", len(public))
}

// handlerFuncNames returns every method name in the api package mapped to its body
// source, so a guard can ask whether a specific handler calls something.
func handlerFuncNames(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string]string{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(".", e.Name())
		src, err := os.ReadFile(path) // #nosec G304 -- reads this package's own sources in a test (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue
			}
			start := fset.Position(fn.Body.Pos()).Offset
			end := fset.Position(fn.Body.End()).Offset
			if start >= 0 && end <= len(src) && start < end {
				out[fn.Name.Name] = string(src[start:end])
			}
		}
	}
	return out
}
