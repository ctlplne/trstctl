// Package keymaterial implements the AN-8 architecture rule: in packages that
// handle secret key material, key bytes must live in []byte (which can be
// mlock'd, marked non-dumpable, and explicitly zeroed), never in string (which
// Go's garbage collector may copy freely and which cannot be wiped).
//
// A package is in scope two ways:
//
//   - by default, if it is one of the canonical secret-byte primitives whose
//     entire purpose is to hold raw key material (internal/crypto/secret,
//     internal/crypto/seal). These are fail-closed: deleting their
//     //trstctl:keymaterial marker does NOT disable the rule (ARCH-004), so the
//     AN-8 guarantee on the real key buffers cannot be silently turned off.
//   - by default, if it is the signing service package and the identifier names
//     raw signer private-key custody. Opaque signer handles and socket paths are
//     strings by design; raw private-key material is not.
//   - by opt-in, if it carries the //trstctl:keymaterial marker. The marker
//     brings additional packages under the rule as the key-handling surface
//     grows; it can only make the rule apply, never silence it.
//
// Once a package is in scope, any field, parameter, or result whose type is
// string-backed is a violation. Detection is type-resolved (ARCH-001), not a
// bare `field.Type == ident "string"` check, so it also catches:
//
//   - named string types (`type Secret string`; a field `Material Secret`);
//   - composite types built from string ([]string, map[string]string,
//     map[K]string, [N]string);
//   - pointers to any of the above (*string, *Secret, *[]string).
//
// The earlier revision flagged only the literal identifier "string", so a
// key-handling package could store secret bytes behind any of those constructs
// and pass CI. That false-negative is closed here.
package keymaterial

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"

	"trstctl.com/trstctl/tools/trstctllint/internal/directive"
)

const keyMaterialMarker = "trstctl:keymaterial"

// defaultKeyMaterialPkgs are the canonical secret-byte primitive packages that
// are key-handling by construction. They are in scope whether or not they carry
// the marker, so the AN-8 rule on the real secret buffers is fail-closed: a
// forgotten or deleted marker cannot silently turn enforcement off (ARCH-004).
// Extending this set is a deliberate, reviewed change here, with a fixture.
var defaultKeyMaterialPkgs = map[string]bool{
	"trstctl.com/trstctl/internal/crypto/secret": true,
	"trstctl.com/trstctl/internal/crypto/seal":   true,
}

var signingKeyCustodyPkgs = map[string]bool{
	"trstctl.com/trstctl/internal/signing": true,
}

var signingKeyMaterialNameFragments = []string{
	"keymaterial",
	"pkcs8",
	"plaintextkey",
	"privatekey",
	"privatepem",
	"rawkey",
	"sealedkey",
	"secretkey",
}

var secretSurfacePkgs = map[string]bool{
	"trstctl.com/trstctl/internal/api":        true,
	"trstctl.com/trstctl/internal/auth":       true,
	"trstctl.com/trstctl/internal/authmethod": true,
}

var secretSurfaceNames = map[string]bool{
	"Credential": true,
	"PrivateKey": true,
	"Token":      true,
	"Value":      true,
}

var secretConversionIdents = map[string]bool{
	"credential": true,
	"keyPEM":     true,
	"token":      true,
	"value":      true,
}

var secretConversionSelectors = map[string]bool{
	"cred.Secret":    true,
	"req.Credential": true,
	"req.Token":      true,
	"req.Value":      true,
}

var providerCredentialNames = map[string]bool{
	"SecretAccessKey": true,
	"SessionToken":    true,
	"BearerToken":     true,
	"APIKey":          true,
	"APIToken":        true,
	"ClientToken":     true,
	"ClientSecret":    true,
	"AccessToken":     true,
	"apiKey":          true,
}

// Analyzer enforces AN-8.
var Analyzer = &analysis.Analyzer{
	Name: "keymaterial",
	Doc:  "AN-8: key-handling packages (secret/seal and signer custody by default, or //trstctl:keymaterial) must not use string for key material; use []byte.",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	inKeyMaterialScope := inScope(pass)
	inSigningKeyCustodyScope := signingKeyCustodyPkgs[pass.Pkg.Path()]
	inSecretSurfaceScope := secretSurfacePkgs[pass.Pkg.Path()]
	inDeploymentConnectorScope := strings.HasPrefix(pass.Pkg.Path(), "trstctl.com/trstctl/internal/connector/")
	inProviderCredentialScope := providerCredentialScope(pass.Pkg.Path())
	if !inKeyMaterialScope && !inSigningKeyCustodyScope && !inSecretSurfaceScope && !inDeploymentConnectorScope && !inProviderCredentialScope {
		return nil, nil
	}
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Field:
				if inKeyMaterialScope && isStringBacked(pass, x.Type) {
					pass.Reportf(x.Type.Pos(),
						"key-handling package must not use string for key material; use []byte (AN-8)")
				}
				if inSigningKeyCustodyScope && signingKeyMaterialFieldName(x) && isStringBacked(pass, x.Type) {
					pass.Reportf(x.Type.Pos(),
						"signing key custody must not use string-backed key material; use []byte or crypto.LockedSigner-backed storage (AN-8)")
				}
				if inSecretSurfaceScope && secretSurfaceFieldName(x) && isStringBacked(pass, x.Type) {
					pass.Reportf(x.Type.Pos(),
						"secret-bearing API/auth field must not use string; use byte-backed JSON/credential handling (AN-8)")
				}
				if inProviderCredentialScope && !isTestFile(pass, x) && providerCredentialName(x) && isStringBacked(pass, x.Type) {
					pass.Reportf(x.Type.Pos(),
						"provider credential field must not use string; use byte-backed credential handling and edge-only header strings (AN-8)")
				}
			case *ast.CallExpr:
				if inSecretSurfaceScope && isSecretStringConversion(x) {
					pass.Reportf(x.Pos(),
						"secret-bearing API/auth code must not convert secret bytes to string; keep material in []byte (AN-8)")
				}
				if inDeploymentConnectorScope && isDeploymentKeyStringConversion(x) {
					pass.Reportf(x.Pos(),
						"deployment connector must not convert Deployment.KeyPEM to string/base64 string; use byte-backed encoders and wipe edge buffers (AN-8)")
				}
			}
			return true
		})
	}
	return nil, nil
}

func providerCredentialScope(pkg string) bool {
	return strings.HasPrefix(pkg, "trstctl.com/trstctl/internal/kms/") ||
		strings.HasPrefix(pkg, "trstctl.com/trstctl/internal/dns/") ||
		strings.HasPrefix(pkg, "trstctl.com/trstctl/internal/notify/") ||
		strings.HasPrefix(pkg, "trstctl.com/trstctl/internal/connector/") ||
		strings.HasPrefix(pkg, "trstctl.com/trstctl/internal/ca/")
}

func providerCredentialName(field *ast.Field) bool {
	for _, name := range field.Names {
		if providerCredentialNames[name.Name] {
			return true
		}
	}
	return false
}

func isTestFile(pass *analysis.Pass, n ast.Node) bool {
	return strings.HasSuffix(pass.Fset.Position(n.Pos()).Filename, "_test.go")
}

func secretSurfaceFieldName(field *ast.Field) bool {
	for _, name := range field.Names {
		if secretSurfaceNames[name.Name] {
			return true
		}
	}
	return false
}

func signingKeyMaterialFieldName(field *ast.Field) bool {
	for _, name := range field.Names {
		normalized := strings.ToLower(name.Name)
		for _, fragment := range signingKeyMaterialNameFragments {
			if strings.Contains(normalized, fragment) {
				return true
			}
		}
	}
	return false
}

func isSecretStringConversion(call *ast.CallExpr) bool {
	if len(call.Args) != 1 {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	if !ok || id.Name != "string" {
		return false
	}
	return isSecretConversionArg(call.Args[0])
}

func isSecretConversionArg(expr ast.Expr) bool {
	switch x := expr.(type) {
	case *ast.Ident:
		return secretConversionIdents[x.Name]
	case *ast.SelectorExpr:
		base, ok := x.X.(*ast.Ident)
		return ok && secretConversionSelectors[base.Name+"."+x.Sel.Name]
	default:
		return false
	}
}

func isDeploymentKeyStringConversion(call *ast.CallExpr) bool {
	if len(call.Args) != 1 || !isDeploymentKeyPEM(call.Args[0]) {
		return false
	}
	if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "string" {
		return true
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "EncodeToString" {
		return false
	}
	stdEncoding, ok := sel.X.(*ast.SelectorExpr)
	if !ok || stdEncoding.Sel.Name != "StdEncoding" {
		return false
	}
	pkg, ok := stdEncoding.X.(*ast.Ident)
	return ok && pkg.Name == "base64"
}

func isDeploymentKeyPEM(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "KeyPEM" {
		return false
	}
	base, ok := sel.X.(*ast.Ident)
	return ok && base.Name == "dep"
}

// inScope reports whether the package is subject to AN-8: either it is a
// default-on secret primitive (fail-closed), or it opts in with the marker.
func inScope(pass *analysis.Pass) bool {
	if defaultKeyMaterialPkgs[pass.Pkg.Path()] {
		return true
	}
	return directive.Present(pass.Files, keyMaterialMarker)
}

// isStringBacked reports whether the type denoted by expr is, or is built out
// of, string — so that secret material cannot hide behind a named type, a
// slice/map/array of strings, or a pointer to any of those. Resolution is by
// type (pass.TypesInfo), so it sees through aliases and named types rather than
// matching the source spelling "string".
func isStringBacked(pass *analysis.Pass, expr ast.Expr) bool {
	tv, ok := pass.TypesInfo.Types[expr]
	if !ok || tv.Type == nil {
		// No type information (e.g. a fixture that does not type-check
		// cleanly): fall back to a syntactic check so the literal `string`
		// is still caught.
		id, ok := expr.(*ast.Ident)
		return ok && id.Name == "string"
	}
	return typeIsStringBacked(tv.Type, make(map[types.Type]bool))
}

// typeIsStringBacked walks a go/types Type and reports whether it ultimately
// rests on string: the type itself (incl. a named type whose underlying is
// string), or the element/value type of a slice, array, map, or pointer. The
// seen set guards against recursive named types.
func typeIsStringBacked(t types.Type, seen map[types.Type]bool) bool {
	if t == nil || seen[t] {
		return false
	}
	seen[t] = true

	// A named or basic type whose underlying is string (catches both
	// `string` itself and `type Secret string`).
	if basic, ok := t.Underlying().(*types.Basic); ok {
		return basic.Kind() == types.String
	}

	switch u := t.Underlying().(type) {
	case *types.Slice:
		return typeIsStringBacked(u.Elem(), seen)
	case *types.Array:
		return typeIsStringBacked(u.Elem(), seen)
	case *types.Pointer:
		return typeIsStringBacked(u.Elem(), seen)
	case *types.Map:
		// A map whose VALUE is string-backed holds secret string material
		// (map[string]string, map[K]Secret). The key is treated as a label
		// (a handle/id), so a handle-keyed byte map (map[string][]byte) stays
		// allowed — the secret there lives in the []byte value, not the key.
		return typeIsStringBacked(u.Elem(), seen)
	default:
		return false
	}
}
