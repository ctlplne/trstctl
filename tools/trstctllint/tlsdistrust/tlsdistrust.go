// SPDX-License-Identifier: BUSL-1.1

// Package tlsdistrust keeps credentialed raw TLS clients behind trust's
// constructor and HTTP TLS configuration overrides behind netsec. A client
// can verify the host yet still omit trstctl's operator and shipped CA
// distrust list (CR-071).
package tlsdistrust

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const (
	trustPath     = "trstctl.com/trstctl/internal/crypto/trust"
	trustTestPath = "trstctl.com/trstctl/internal/crypto/trust/trusttest"
	probePath     = "trstctl.com/trstctl/internal/crypto/tlsprobe"
	mtlsPath      = "trstctl.com/trstctl/internal/crypto/mtls"
	netsecPath    = "trstctl.com/trstctl/internal/netsec"
)

// Analyzer rejects direct client-side crypto/tls construction outside the
// hardened boundary and direct HTTP TLS config overrides outside its builders.
// Read-only discovery probes send no application data.
var Analyzer = &analysis.Analyzer{
	Name: "tlsdistrust",
	Doc:  "CR-071: credentialed raw TLS clients must use internal/crypto/trust constructors",
	Run:  run,
}

func run(pass *analysis.Pass) (any, error) {
	if pass.Pkg.Path() == trustPath || pass.Pkg.Path() == probePath || pass.Pkg.Path() == trustTestPath {
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
				if pass.Pkg.Path() != mtlsPath && pass.Pkg.Path() != netsecPath && isHTTPTransport(pass.TypesInfo.TypeOf(node)) {
					for _, elt := range node.Elts {
						kv, ok := elt.(*ast.KeyValueExpr)
						if key, isIdent := kv.Key.(*ast.Ident); ok && isIdent && key.Name == "TLSClientConfig" {
							pass.Reportf(kv.Pos(), "direct HTTP TLSClientConfig override bypasses the runtime distrust list (CR-071); use netsec.AdoptTLSConfig")
						}
					}
				}
			case *ast.ValueSpec:
				if node.Type != nil && len(node.Values) == 0 && isTLSDialer(pass.TypesInfo.TypeOf(node.Type)) {
					pass.Reportf(node.Pos(), "direct crypto/tls.Dialer bypasses the runtime distrust list (CR-071); use internal/crypto/trust")
				}
			case *ast.AssignStmt:
				if pass.Pkg.Path() == mtlsPath || pass.Pkg.Path() == netsecPath {
					return true
				}
				for _, lhs := range node.Lhs {
					selector, ok := lhs.(*ast.SelectorExpr)
					if ok && selector.Sel.Name == "TLSClientConfig" && isHTTPTransport(pass.TypesInfo.TypeOf(selector.X)) {
						pass.Reportf(selector.Pos(), "direct HTTP TLSClientConfig override bypasses the runtime distrust list (CR-071); use netsec.AdoptTLSConfig")
					}
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

func isHTTPTransport(t types.Type) bool {
	if pointer, ok := t.(*types.Pointer); ok {
		t = pointer.Elem()
	}
	named, ok := t.(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "net/http" && named.Obj().Name() == "Transport"
}
