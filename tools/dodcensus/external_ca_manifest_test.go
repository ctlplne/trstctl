// SPDX-License-Identifier: MPL-2.0

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestExternalCAManifestMatchesProductionAssemblyAndRuntimeBinding(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadManifest(filepath.Join(repo, "tools", "dodcensus", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	profile := manifest.BuildProfiles[manifest.DefaultBuildProfile]
	checked := 0
	for _, entry := range manifest.Entries {
		if !strings.HasPrefix(entry.ID, "external_ca.") {
			continue
		}
		checked++
		if evidence := inspectAssembly(repo, entry, profile); !evidence.OK {
			t.Errorf("%s assembly: %s; required=%v found=%v", entry.ID, evidence.Detail, evidence.Required, evidence.Found)
		}
		if evidence := inspectRuntimeBinding(repo, entry, manifest.Substrates); !evidence.OK {
			t.Errorf("%s runtime: %s; required=%v found=%v", entry.ID, evidence.Detail, evidence.Required, evidence.Found)
		}
	}
	if checked != 15 {
		t.Fatalf("external CA manifest entries = %d, want registry + 14 providers", checked)
	}
}

func TestExternalCARuntimeListsConfiguredRegistryBeforeIssuance(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repo, "internal", "server", "dod_external_ca_runtime_test.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := map[string]*ast.FuncDecl{}
	for _, declaration := range parsed.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil {
			functions[function.Name.Name] = function
		}
	}
	runtimeTest := functions["TestDODExternalCAUniversalProductionAssembly"]
	catalog := functions["dodAssertExternalCACatalog"]
	if runtimeTest == nil || catalog == nil {
		t.Fatal("external-CA runtime test or catalog assertion helper is missing")
	}

	var catalogCall, firstIssuance token.Pos
	ast.Inspect(runtimeTest.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch name := expressionName(call.Fun); {
		case name == "dodAssertExternalCACatalog":
			if catalogCall == token.NoPos || call.Pos() < catalogCall {
				catalogCall = call.Pos()
			}
		case strings.HasPrefix(name, "dodProveExternalCA"):
			if firstIssuance == token.NoPos || call.Pos() < firstIssuance {
				firstIssuance = call.Pos()
			}
		}
		return true
	})
	if catalogCall == token.NoPos || firstIssuance == token.NoPos || catalogCall >= firstIssuance {
		t.Fatalf("configured external-CA catalog assertion must execute before issuance: catalog=%d issuance=%d", catalogCall, firstIssuance)
	}

	var getCatalog, assembledHandler, registryAssertion, availableAssertion bool
	ast.Inspect(catalog.Body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.CallExpr:
			if expressionName(value.Fun) == "http.NewRequest" && len(value.Args) == 3 && expressionName(value.Args[0]) == "http.MethodGet" && containsLiteral(value.Args[1:2], "/api/v1/external-cas") {
				getCatalog = true
			}
			selector, ok := value.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "ServeHTTP" {
				break
			}
			handler, ok := selector.X.(*ast.CallExpr)
			assembledHandler = assembledHandler || (ok && expressionName(handler.Fun) == "srv.Handler")
		case *ast.BinaryExpr:
			registryAssertion = registryAssertion || astStringEquality(value, "item.ID", "registry")
			availableAssertion = availableAssertion || astStringEquality(value, "item.Status", "available")
		}
		return true
	})
	if !getCatalog || !assembledHandler || !registryAssertion || !availableAssertion {
		t.Fatalf("catalog proof must GET the assembled route and require configured registry availability: get=%v handler=%v registry=%v available=%v", getCatalog, assembledHandler, registryAssertion, availableAssertion)
	}
}

func astStringEquality(expression *ast.BinaryExpr, field, want string) bool {
	if expression.Op != token.EQL {
		return false
	}
	for _, pair := range [][2]ast.Expr{{expression.X, expression.Y}, {expression.Y, expression.X}} {
		literal, ok := pair[1].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING || expressionName(pair[0]) != field {
			continue
		}
		value, err := strconv.Unquote(literal.Value)
		if err == nil && value == want {
			return true
		}
	}
	return false
}
