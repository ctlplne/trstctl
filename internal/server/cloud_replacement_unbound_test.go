// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/outboundcred"
)

// CR-008 (design D4): a replace_key that an unbound writer or role-reader
// reference stops sends nothing more. After preparing began, the replacement
// may already be published; while Queued, only if an earlier attempt stopped
// after queueing it. Either way the attempt did not retire the old key, and the
// recorded failure says to revoke it only once the replacement's rotation
// completed and its consumer adopted it; any other failure keeps its own text.
func TestReplaceKeyStoppedByAnUnboundReferenceSaysTheOldKeyIsStillActiveCR008(t *testing.T) {
	unbound := fmt.Errorf("%w: the operator has not bound it to this tenant for the cloud_machine_change integration", outboundcred.ErrNotBound)
	err := replacementStoppedUnbound(unbound)
	if !errors.Is(err, outboundcred.ErrNotBound) {
		t.Fatalf("the failure no longer says the reference is unbound: %v", err)
	}
	// Once the change has failed, its replacement rotation may still complete
	// (past verification) or end without the replacement current, so the
	// advice to revoke the old key always waits for a completed, adopted
	// replacement.
	const advice = "propose a revoke_key only if the replacement's publication completed and its consumer adopted it, otherwise propose the replace_key again"
	for _, want := range []string{
		"the replacement may already be published",
		"this attempt did not retire the old key",
		advice,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure %q does not say %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "rescan and propose a revoke_key") {
		t.Errorf("the failure advises an outright revoke: %v", err)
	}
	drifted := errors.New("approved native replacement role identity or policy changed")
	if got := replacementStoppedUnbound(drifted); got != drifted {
		t.Fatalf("a failure that is not about a binding was rewritten: %v", got)
	}
	// Still Queued, a first delivery has published nothing: the text says so
	// and carries the same conditional advice.
	queued := replacementStoppedUnboundBeforePreparing(unbound)
	if !errors.Is(queued, outboundcred.ErrNotBound) || strings.Contains(queued.Error(), "may already be published") {
		t.Fatalf("a Queued stop = %v", queued)
	}
	for _, want := range []string{
		"published only if an earlier attempt stopped after queueing it",
		"this attempt did not retire the old key",
		advice,
	} {
		if !strings.Contains(queued.Error(), want) {
			t.Errorf("the Queued failure %q does not say %q", queued, want)
		}
	}
	if got := replacementStoppedUnboundBeforePreparing(drifted); got != drifted {
		t.Fatalf("a Queued failure that is not about a binding was rewritten: %v", got)
	}

	// Each stop says what it may have left: the role readback in the prepare and
	// retire phases that the replacement may already be published, the readback
	// of a Queued change that it was published only after an earlier stop; the
	// writer check the one or the other by the change's state.
	fset := token.NewFileSet()
	worker, err := parser.ParseFile(fset, "cloud_replacement_worker.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	phases := map[string]string{}
	for _, decl := range worker.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "handleCloudReplacement" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			clause, ok := n.(*ast.CaseClause)
			if !ok || len(clause.List) != 1 {
				return true
			}
			lit, ok := clause.List[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			phase, _ := strconv.Unquote(lit.Value)
			readback, wrapped := false, "plain"
			for _, stmt := range clause.Body {
				ast.Inspect(stmt, func(n ast.Node) bool {
					if call, ok := n.(*ast.CallExpr); ok {
						switch name := replacementCallee(call); name {
						case "replacementRoleReadback":
							readback = true
						case "replacementStoppedUnbound", "replacementStoppedUnboundBeforePreparing":
							wrapped = name
						}
					}
					return true
				})
			}
			if readback {
				phases[phase] = wrapped
			}
			return true
		})
	}
	want := map[string]string{"": "replacementStoppedUnboundBeforePreparing", "prepare": "replacementStoppedUnbound", "retire": "replacementStoppedUnbound"}
	if fmt.Sprint(phases) != fmt.Sprint(want) {
		t.Fatalf("role readback phases (phase: its unbound wording) = %v, want %v", phases, want)
	}
	changes, err := parser.ParseFile(fset, "cloud_machine_changes.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	writer := map[string]bool{}
	for _, decl := range changes.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "handleCloudMachineChange" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			ifStmt, ok := n.(*ast.IfStmt)
			if !ok {
				return true
			}
			cond := replacementSelectors(ifStmt.Cond)
			if !strings.Contains(cond, "change.ReplaceKey") {
				return true
			}
			// value.Intent.Action == change.ReplaceKey, not its negation.
			if eq, ok := ifStmt.Cond.(*ast.BinaryExpr); !ok || eq.Op != token.EQL {
				return true
			}
			// The Queued wording sits under a Queued condition; the other one
			// after it.
			ast.Inspect(ifStmt.Body, func(n ast.Node) bool {
				if inner, ok := n.(*ast.IfStmt); ok && strings.Contains(replacementSelectors(inner.Cond), "change.Queued") {
					// value.State == change.Queued, not its negation.
					if cond, ok := inner.Cond.(*ast.BinaryExpr); !ok || cond.Op != token.EQL {
						return true
					}
					// The Queued branch returns its own wording rather than
					// falling through to the other one.
					for _, stmt := range inner.Body.List {
						ret, ok := stmt.(*ast.ReturnStmt)
						if !ok {
							continue
						}
						ast.Inspect(ret, func(n ast.Node) bool {
							if call, ok := n.(*ast.CallExpr); ok && replacementCallee(call) == "replacementStoppedUnboundBeforePreparing" {
								writer["queued"] = true
							}
							return true
						})
					}
					return false
				}
				if call, ok := n.(*ast.CallExpr); ok && replacementCallee(call) == "replacementStoppedUnbound" {
					writer["past queued"] = true
				}
				return true
			})
			return true
		})
	}
	if !writer["queued"] || !writer["past queued"] {
		t.Fatalf("the writer check of a replace_key words a Queued and a later stop as %v, want both", writer)
	}
}

func replacementCallee(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// replacementSelectors renders the selector expressions in e (pkg.Name),
// enough to read a condition's constants.
func replacementSelectors(e ast.Expr) string {
	var parts []string
	ast.Inspect(e, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok {
				parts = append(parts, pkg.Name+"."+sel.Sel.Name)
			}
		}
		return true
	})
	return strings.Join(parts, " ")
}
