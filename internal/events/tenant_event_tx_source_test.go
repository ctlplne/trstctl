// SPDX-License-Identifier: BUSL-1.1

package events_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// A producer that appends inside a tenant transaction must pass a context
// bound to that transaction to the shared event admission path.
func TestTenantTransactionEventAppendUsesScopedContext(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	for _, dir := range []string{"internal", "cmd", "ee"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				method, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || method.Sel.Name != "WithTenant" || len(call.Args) != 3 {
					return true
				}
				callback, ok := call.Args[2].(*ast.FuncLit)
				if !ok {
					return true
				}
				ast.Inspect(callback.Body, func(bodyNode ast.Node) bool {
					appendCall, ok := bodyNode.(*ast.CallExpr)
					if !ok {
						return true
					}
					appendMethod, ok := appendCall.Fun.(*ast.SelectorExpr)
					if ok && appendMethod.Sel.Name == "Append" {
						t.Errorf("%s: event append inside WithTenant must use WithTenantEvent", fset.Position(appendCall.Pos()))
					}
					return true
				})
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
