// SPDX-License-Identifier: BUSL-1.1

// Package servedmutation finds the functions that implement served mutation
// endpoints.
//
// The route registry is the production source of truth for HTTP mutations. The
// //trstctl:mutation marker remains a readable local declaration, but analyzers
// must also consume route{mutation: true, handler: ...} entries so a new route
// cannot accidentally bypass AN-2 or AN-5 by omitting the marker.
package servedmutation

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"

	"trstctl.com/trstctl/tools/trstctllint/internal/directive"
)

// Marker is the shared marker used by the AN-2 and AN-5 analyzers.
const Marker = "trstctl:mutation"

// Funcs returns the union of explicitly marked mutation functions and handlers
// referenced by route literals with mutation: true.
func Funcs(pass *analysis.Pass) map[*ast.FuncDecl]struct{} {
	decls := funcDecls(pass)
	out := make(map[*ast.FuncDecl]struct{})
	for _, decl := range decls.byDecl {
		if directive.OnFunc(decl, Marker) {
			out[decl] = struct{}{}
		}
	}
	for _, handler := range routeMutationHandlers(pass) {
		if decl := decls.byFunc[handler]; decl != nil {
			out[decl] = struct{}{}
			continue
		}
		// Fallback for analyzer fixtures where type information can be sparse.
		if decl := decls.byName[handler.Name()]; decl != nil {
			out[decl] = struct{}{}
		}
	}
	return out
}

type declarations struct {
	byDecl []*ast.FuncDecl
	byFunc map[*types.Func]*ast.FuncDecl
	byName map[string]*ast.FuncDecl
}

func funcDecls(pass *analysis.Pass) declarations {
	out := declarations{
		byFunc: make(map[*types.Func]*ast.FuncDecl),
		byName: make(map[string]*ast.FuncDecl),
	}
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			out.byDecl = append(out.byDecl, fn)
			out.byName[fn.Name.Name] = fn
			if obj, ok := pass.TypesInfo.Defs[fn.Name].(*types.Func); ok {
				out.byFunc[obj] = fn
			}
		}
	}
	return out
}

func routeMutationHandlers(pass *analysis.Pass) []*types.Func {
	var out []*types.Func
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			handler, mutates := routeLiteral(lit)
			if !mutates || handler == nil {
				return true
			}
			if fn := calleeFunc(pass, handler); fn != nil {
				out = append(out, fn)
			}
			return true
		})
	}
	return out
}

func routeLiteral(lit *ast.CompositeLit) (ast.Expr, bool) {
	var handler ast.Expr
	mutates := false
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "handler":
			handler = kv.Value
		case "mutation":
			if b, ok := kv.Value.(*ast.Ident); ok && b.Name == "true" {
				mutates = true
			}
		}
	}
	return handler, mutates
}

func calleeFunc(pass *analysis.Pass, expr ast.Expr) *types.Func {
	switch e := expr.(type) {
	case *ast.Ident:
		if obj, ok := pass.TypesInfo.Uses[e].(*types.Func); ok {
			return obj
		}
		if obj, ok := pass.TypesInfo.Defs[e].(*types.Func); ok {
			return obj
		}
	case *ast.SelectorExpr:
		if sel, ok := pass.TypesInfo.Selections[e]; ok {
			if fn, ok := sel.Obj().(*types.Func); ok {
				return fn
			}
		}
		if obj, ok := pass.TypesInfo.Uses[e.Sel].(*types.Func); ok {
			return obj
		}
	}
	return nil
}
