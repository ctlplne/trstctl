// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strconv"
	"testing"
)

// Every dynamic secret type has a validator of its own: one of the A239
// library's (a239ProviderValidators) or a case in validateDynamicProvider's
// switch. A type in neither would pass with only the shared field checks.
func TestEveryDynamicSecretTypeHasAValidator(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "secret_integrations.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	switchTypes := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "validateDynamicProvider" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok || sw.Tag == nil || types.ExprString(sw.Tag) != "c.Type" {
				return true
			}
			for _, stmt := range sw.Body.List {
				for _, expr := range stmt.(*ast.CaseClause).List {
					if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if value, err := strconv.Unquote(lit.Value); err == nil {
							switchTypes[value] = true
						}
					}
				}
			}
			return false
		})
	}
	if len(switchTypes) == 0 {
		t.Fatal("validateDynamicProvider's switch on c.Type was not found in secret_integrations.go")
	}
	for typ := range dynamicSecretTypes {
		if _, library := a239ProviderValidators[typ]; !library && !switchTypes[typ] {
			t.Errorf("dynamic secret type %q has no validator: add one to a239ProviderValidators or a case to validateDynamicProvider", typ)
		}
	}
}
