// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/outboundcred"
)

// CR-008: every worker scope names an integration kind a binding may name: a
// constant from outboundcred, or, at the few sites that run a stored source,
// that source's own kind. A kind outside the allow-list can never match a
// binding, so a stored source of any other kind resolves nothing.
func TestEveryOutboundCredentialScopeNamesABindableKind(t *testing.T) {
	// The functions that scope a stored source by its own kind.
	dynamic := map[string]bool{
		"executeDiscoveryRun": true, "handleOAuthProviderAction": true, "handleCloudKeyAction": true,
		"handleScanAnnotation": true, "handleAttackPathValidate": true, "replacementRoleReadback": true,
		"outboundCredentialScope": true, // the dispatcher's wrapper passes its argument on
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	calls := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name) // #nosec G304 -- the census reads this package's own source files by glob (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var callee string
				switch f := call.Fun.(type) {
				case *ast.Ident:
					callee = f.Name
				case *ast.SelectorExpr:
					callee = f.Sel.Name
				}
				if callee != "withOutboundCredentialScope" && callee != "outboundCredentialScope" {
					return true
				}
				calls++
				kind := call.Args[len(call.Args)-1]
				where := fset.Position(call.Pos()).String() + " in " + fn.Name.Name
				switch k := kind.(type) {
				case *ast.BasicLit:
					value, err := strconv.Unquote(k.Value)
					if err != nil || !outboundcred.KnownIntegration(value) {
						t.Errorf("%s scopes the literal kind %s, which no binding may name", where, k.Value)
					}
				case *ast.SelectorExpr:
					if pkg, ok := k.X.(*ast.Ident); ok && pkg.Name == "outboundcred" && strings.HasPrefix(k.Sel.Name, "Integration") {
						return true
					}
					if !dynamic[fn.Name.Name] {
						t.Errorf("%s scopes %s; only the stored-source sites may pass a kind that is not an outboundcred constant", where, kindString(k))
					}
				default:
					if !dynamic[fn.Name.Name] {
						t.Errorf("%s scopes a computed kind; only the stored-source sites may", where)
					}
				}
				return true
			})
		}
	}
	if calls < 10 {
		t.Fatalf("found %d worker scope calls; the census lost track of them", calls)
	}
	if got := outboundcred.Integrations(); !slices.Contains(got, outboundcred.IntegrationCloudCertificate) {
		t.Fatalf("bindable kinds %v lack cloud_certificate", got)
	}
}

func kindString(e *ast.SelectorExpr) string {
	if x, ok := e.X.(*ast.Ident); ok {
		return x.Name + "." + e.Sel.Name
	}
	return e.Sel.Name
}
