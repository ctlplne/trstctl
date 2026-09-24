// SPDX-License-Identifier: BUSL-1.1

//go:build !trstctl_core

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Enterprise/Provider inherit both features, so tier-only runtime tests cannot
// detect accidentally gating audit packaging under governance. Pin the specific
// construction block as well as exercising the real licensed/unlicensed assembly.
func TestAuditComplianceFactoriesHaveOneFeatureGate(t *testing.T) {
	tree, err := parser.ParseFile(token.NewFileSet(), "ee_attach.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	count := func(node ast.Node) map[string]int {
		result := map[string]int{}
		ast.Inspect(node, func(n ast.Node) bool {
			assignment, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, left := range assignment.Lhs {
				field, ok := left.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				base, ok := field.X.(*ast.Ident)
				if ok && base.Name == "deps" {
					result[field.Sel.Name]++
				}
			}
			return true
		})
		return result
	}
	total := count(tree)
	protected := map[string]int{}
	blocks := 0
	ast.Inspect(tree, func(n ast.Node) bool {
		conditional, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		grantsAudit := false
		ast.Inspect(conditional.Cond, func(c ast.Node) bool {
			call, ok := c.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			method, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || method.Sel.Name != "Has" {
				return true
			}
			receiver, ok := method.X.(*ast.Ident)
			if !ok || receiver.Name != "lic" {
				return true
			}
			feature, ok := call.Args[0].(*ast.SelectorExpr)
			if ok && feature.Sel.Name == "FeatureAuditCompliance" {
				grantsAudit = true
			}
			return true
		})
		if grantsAudit {
			blocks++
			for field, n := range count(conditional.Body) {
				protected[field] += n
			}
		}
		return true
	})
	if blocks != 1 {
		t.Fatalf("audit-compliance license blocks=%d, want exactly one", blocks)
	}
	for _, field := range []string{"AuditComplianceFactory", "GovernanceFactory"} {
		if total[field] != 1 || protected[field] != 1 {
			t.Fatalf("%s assignments: total=%d audit-gated=%d", field, total[field], protected[field])
		}
	}
	if protected["GovernancePolicySource"] != 0 {
		t.Fatal("audit compliance incorrectly owns the independent governance policy")
	}
}
