// SPDX-License-Identifier: BUSL-1.1

// Package tlsdistrust keeps credentialed raw TLS clients behind trust's
// constructor. A direct crypto/tls client can verify the host yet still omit
// trstctl's operator and shipped CA distrust list (CR-071).
package tlsdistrust

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const (
	trustPath = "trstctl.com/trstctl/internal/crypto/trust"
	probePath = "trstctl.com/trstctl/internal/crypto/tlsprobe"
)

// Analyzer rejects direct client-side crypto/tls construction outside the
// hardened boundary. The two exceptions are the boundary itself and the
// read-only discovery probe, which sends no application data.
var Analyzer = &analysis.Analyzer{
	Name: "tlsdistrust",
	Doc:  "CR-071: credentialed raw TLS clients must use internal/crypto/trust constructors",
	Run:  run,
}

func run(pass *analysis.Pass) (any, error) {
	if pass.Pkg.Path() == trustPath || pass.Pkg.Path() == probePath {
		return nil, nil
	}
	for _, file := range pass.Files {
		if strings.HasSuffix(pass.Fset.File(file.Pos()).Name(), "_test.go") {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				if builtin, ok := node.Fun.(*ast.Ident); ok && builtin.Name == "new" && len(node.Args) == 1 && isTLSDialer(pass.TypesInfo.TypeOf(node.Args[0])) {
					pass.Reportf(node.Pos(), "direct crypto/tls.Dialer bypasses the runtime distrust list (CR-071); use internal/crypto/trust")
					return true
				}
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				fn, ok := pass.TypesInfo.Uses[sel.Sel].(*types.Func)
				if ok && fn.Pkg() != nil && fn.Pkg().Path() == "crypto/tls" {
					switch fn.Name() {
					case "Client", "Dial", "DialWithDialer":
						pass.Reportf(node.Pos(), "direct crypto/tls client bypasses the runtime distrust list (CR-071); use internal/crypto/trust")
					}
				}
			case *ast.CompositeLit:
				if isTLSDialer(pass.TypesInfo.TypeOf(node)) {
					pass.Reportf(node.Pos(), "direct crypto/tls.Dialer bypasses the runtime distrust list (CR-071); use internal/crypto/trust")
				}
			case *ast.ValueSpec:
				if node.Type != nil && len(node.Values) == 0 && isTLSDialer(pass.TypesInfo.TypeOf(node.Type)) {
					pass.Reportf(node.Pos(), "direct crypto/tls.Dialer bypasses the runtime distrust list (CR-071); use internal/crypto/trust")
				}
			}
			return true
		})
	}
	return nil, nil
}

func isTLSDialer(t types.Type) bool {
	named, ok := t.(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "crypto/tls" && named.Obj().Name() == "Dialer"
}
