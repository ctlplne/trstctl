// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestFromZeroReplaysStayBehindTheHeadMemo is the completeness guard for
// AUD-201 follow-up F5/V21: two full-log replay endpoints were memoized and a
// third (mdm_scep) was left unmemoized. Every `.Replay(ctx, 0, ...)` in
// non-test internal/api code must live inside one of the named rebuild
// functions that the shared headMemo drives — a new from-zero replay on a
// request path fails here with instructions, instead of shipping another
// O(entire log) endpoint.
func TestFromZeroReplaysStayBehindTheHeadMemo(t *testing.T) {
	allowed := map[string]bool{
		// vault_compat_state.go: rebuild driven by vaultCompatState.memo.
		"replaySnapshot": true,
		// policy_versions.go: rebuild driven by API.policyVersionMemo.
		"replayPolicyVersions": true,
		// mdm_scep.go: rebuild closure inside the memoized telemetry getter.
		"mdmSCEPTelemetry": true,
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) < 2 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Replay" {
					return true
				}
				lit, ok := call.Args[1].(*ast.BasicLit)
				if !ok || lit.Value != "0" {
					return true
				}
				if !allowed[fn.Name.Name] {
					t.Errorf("%s: %s replays the event log from zero outside the headMemo rebuild set; "+
						"route it through headMemo.get so the projection is cached against the log head (F5/V21)",
						name, fn.Name.Name)
				}
				return true
			})
		}
	}
}
