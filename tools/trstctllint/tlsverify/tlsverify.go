// SPDX-License-Identifier: MPL-2.0

// Package tlsverify implements the SEC-CWE-295 architecture rule: no shipped
// code path may disable TLS certificate verification. `InsecureSkipVerify:
// true` (or an assignment of true to that field) is allowed in exactly one
// production package — internal/crypto/tlsprobe, the discovery prober that
// inventories whatever certificate an endpoint serves without ever trusting
// the connection — and in _test.go files, which speak only to their own local
// listeners. Everywhere else a skipped verification is a served path silently
// accepting any certificate (CWE-295), which is the class this analyzer makes
// extinct rather than re-fixing one call site at a time.
package tlsverify

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const (
	modulePath = "trstctl.com/trstctl"
	// The one sanctioned production package: the discovery prober, whose whole
	// function is to capture the served certificate, valid or not, on a
	// connection that never carries data.
	allowedPkg = modulePath + "/internal/crypto/tlsprobe"
	// The one sanctioned production function outside it: the mtls loopback
	// liveness probe, which checks its own process's ephemeral self-signed
	// listener on localhost and carries no credential and reads no data.
	allowedFuncPkg  = modulePath + "/internal/crypto/mtls"
	allowedFuncName = "LoopbackProbeClient"
)

// Analyzer enforces SEC-CWE-295.
var Analyzer = &analysis.Analyzer{
	Name: "tlsverify",
	Doc:  "CWE-295: InsecureSkipVerify may be set true only in internal/crypto/tlsprobe (the discovery prober) and in _test.go files.",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	if pass.Pkg.Path() == allowedPkg {
		return nil, nil
	}
	for _, file := range pass.Files {
		if strings.HasSuffix(pass.Fset.File(file.Pos()).Name(), "_test.go") {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if fd, ok := n.(*ast.FuncDecl); ok &&
				pass.Pkg.Path() == allowedFuncPkg && fd.Name.Name == allowedFuncName {
				return false // the sanctioned loopback liveness probe
			}
			switch node := n.(type) {
			case *ast.CompositeLit:
				if !isTLSConfig(pass.TypesInfo.TypeOf(node)) {
					return true
				}
				for _, elt := range node.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok || key.Name != "InsecureSkipVerify" {
						continue
					}
					if isTrue(kv.Value) {
						report(pass, kv.Pos())
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "InsecureSkipVerify" {
						continue
					}
					if !isTLSConfig(pass.TypesInfo.TypeOf(sel.X)) {
						continue
					}
					if i < len(node.Rhs) && isTrue(node.Rhs[i]) {
						report(pass, node.Pos())
					}
				}
			}
			return true
		})
	}
	return nil, nil
}

func report(pass *analysis.Pass, pos token.Pos) {
	pass.Reportf(pos,
		"InsecureSkipVerify: true disables TLS certificate verification (CWE-295); only internal/crypto/tlsprobe (the discovery prober) and _test.go files may do this")
}

// isTLSConfig reports whether t is crypto/tls.Config (or a pointer to it).
func isTLSConfig(t types.Type) bool {
	if t == nil {
		return false
	}
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Name() == "Config" && obj.Pkg() != nil && obj.Pkg().Path() == "crypto/tls"
}

func isTrue(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "true"
}
