// SPDX-License-Identifier: MPL-2.0

// Package cryptoagility enforces the PQC-00 design guardrail: trstctl's
// crypto-agility model is compile-time Go interfaces plus dependency injection
// behind internal/crypto, not a runtime plugin/engine/provider registry.
package cryptoagility

import (
	"go/ast"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const (
	modulePath       = "trstctl.com/trstctl"
	cryptoPkg        = modulePath + "/internal/crypto"
	signingPkg       = modulePath + "/internal/signing"
	signerCommandPkg = modulePath + "/cmd/trstctl-signer"
	policyPkg        = modulePath + "/internal/policy"
)

// Analyzer enforces the crypto-agility non-infringement guardrail.
var Analyzer = &analysis.Analyzer{
	Name: "cryptoagility",
	Doc:  "PQC-00: crypto/signing code must use compile-time interfaces and DI, not runtime plugin/provider/engine registries.",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	if !guardedPackage(pass.Pkg.Path()) {
		return nil, nil
	}
	for _, file := range pass.Files {
		checkImports(pass, file)
		checkPackageDecls(pass, file)
	}
	return nil, nil
}

func checkImports(pass *analysis.Pass, file *ast.File) {
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		switch {
		case path == "plugin":
			pass.Reportf(imp.Pos(),
				"import %q is not allowed in the crypto/signer boundary (PQC-00); crypto-agility uses compile-time interfaces and dependency injection, not runtime plugin providers",
				path)
		case isPolicyImport(path):
			pass.Reportf(imp.Pos(),
				"import %q is not allowed in the crypto/signer boundary (PQC-00); policy may pass algorithm parameters to callers but must not control crypto providers",
				path)
		}
	}
}

func checkPackageDecls(pass *analysis.Pass, file *ast.File) {
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			if d.Tok.String() != "var" {
				continue
			}
			checkPackageVars(pass, d)
		case *ast.FuncDecl:
			if d.Recv == nil && isRuntimeRegistrationFunction(d.Name.Name) {
				pass.Reportf(d.Name.Pos(),
					"runtime crypto suite/provider registration function %q is not allowed (PQC-00); add backends by implementing internal/crypto interfaces and injecting them at assembly time",
					d.Name.Name)
			}
		}
	}
}

func checkPackageVars(pass *analysis.Pass, decl *ast.GenDecl) {
	for _, spec := range decl.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, name := range vs.Names {
			if name.Name == "_" || !isRuntimeMutableRegistryVar(name.Name, vs, i) {
				continue
			}
			pass.Reportf(name.Pos(),
				"runtime-mutable crypto provider/engine registry %q is not allowed (PQC-00); use compile-time interfaces plus dependency injection behind internal/crypto",
				name.Name)
		}
	}
}

func guardedPackage(pkgPath string) bool {
	return pkgPath == cryptoPkg ||
		strings.HasPrefix(pkgPath, cryptoPkg+"/") ||
		pkgPath == signingPkg ||
		strings.HasPrefix(pkgPath, signingPkg+"/") ||
		pkgPath == signerCommandPkg ||
		strings.HasPrefix(pkgPath, signerCommandPkg+"/")
}

func isPolicyImport(path string) bool {
	return path == policyPkg || strings.HasPrefix(path, policyPkg+"/")
}

func isRuntimeMutableRegistryVar(name string, vs *ast.ValueSpec, index int) bool {
	n := strings.ToLower(name)
	if strings.Contains(n, "registry") ||
		strings.Contains(n, "registries") ||
		strings.Contains(n, "providers") ||
		strings.Contains(n, "engines") ||
		strings.Contains(n, "backends") {
		return true
	}
	if strings.Contains(n, "provider") ||
		strings.Contains(n, "engine") ||
		strings.Contains(n, "backend") ||
		(strings.Contains(n, "suite") && !strings.Contains(n, "cipher")) {
		return valueSpecLooksMutable(vs, index)
	}
	return false
}

func isRuntimeRegistrationFunction(name string) bool {
	if !strings.HasPrefix(name, "Register") {
		return false
	}
	n := strings.ToLower(name)
	for _, term := range []string{"crypto", "suite", "provider", "engine", "backend", "algorithm"} {
		if strings.Contains(n, term) {
			return true
		}
	}
	return false
}

func valueSpecLooksMutable(vs *ast.ValueSpec, index int) bool {
	if exprLooksMutable(vs.Type) {
		return true
	}
	if index < len(vs.Values) && exprLooksMutable(vs.Values[index]) {
		return true
	}
	return false
}

func exprLooksMutable(expr ast.Expr) bool {
	switch e := expr.(type) {
	case nil:
		return false
	case *ast.MapType:
		return true
	case *ast.ArrayType:
		return e.Len == nil
	case *ast.StarExpr:
		return exprLooksMutable(e.X)
	case *ast.SelectorExpr:
		return e.Sel.Name == "Map"
	case *ast.CompositeLit:
		return exprLooksMutable(e.Type)
	case *ast.CallExpr:
		return callLooksMutable(e)
	case *ast.ParenExpr:
		return exprLooksMutable(e.X)
	default:
		return false
	}
}

func callLooksMutable(call *ast.CallExpr) bool {
	if ident, ok := call.Fun.(*ast.Ident); ok {
		if ident.Name == "make" && len(call.Args) > 0 {
			return exprLooksMutable(call.Args[0])
		}
		return registryFactoryName(ident.Name)
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		return registryFactoryName(sel.Sel.Name)
	}
	return false
}

func registryFactoryName(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "registry") ||
		strings.Contains(n, "provider") ||
		strings.Contains(n, "engine") ||
		strings.Contains(n, "backend")
}
