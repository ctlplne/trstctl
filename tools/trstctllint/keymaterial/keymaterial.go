// SPDX-License-Identifier: MPL-2.0

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

var bearerTokenSignaturePkgs = map[string]bool{
	"trstctl.com/trstctl/internal/agent/enroll": true,
}

var bearerTokenEncodingPkgs = map[string]bool{
	"trstctl.com/trstctl/internal/api":          true,
	"trstctl.com/trstctl/internal/agent/enroll": true,
	"trstctl.com/trstctl/internal/server":       true,
}

var signerAuthorizationTokenStringPkgs = map[string]bool{
	"trstctl.com/trstctl/internal/signing": true,
}

var signerAuthorizationTokenCommandPkgs = map[string]bool{
	"trstctl.com/trstctl/internal/server": true,
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
	inBearerTokenSignatureScope := bearerTokenSignaturePkgs[pass.Pkg.Path()]
	inBearerTokenEncodingScope := bearerTokenEncodingPkgs[pass.Pkg.Path()]
	inSignerAuthorizationTokenStringScope := signerAuthorizationTokenStringPkgs[pass.Pkg.Path()]
	inSignerAuthorizationTokenCommandScope := signerAuthorizationTokenCommandPkgs[pass.Pkg.Path()]
	inDeploymentConnectorScope := strings.HasPrefix(pass.Pkg.Path(), "trstctl.com/trstctl/internal/connector/")
	inProviderCredentialScope := providerCredentialScope(pass.Pkg.Path())
	if !inKeyMaterialScope && !inSigningKeyCustodyScope && !inSecretSurfaceScope && !inBearerTokenSignatureScope && !inBearerTokenEncodingScope && !inSignerAuthorizationTokenStringScope && !inSignerAuthorizationTokenCommandScope && !inDeploymentConnectorScope && !inProviderCredentialScope {
		return nil, nil
	}
	for _, file := range pass.Files {
		inspectWithParent(file, func(n ast.Node, parent ast.Node) bool {
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
			case *ast.TypeSpec:
				if inBearerTokenSignatureScope && !isTestFile(pass, x) {
					reportBearerTokenStructFields(pass, x)
				}
			case *ast.FuncDecl:
				if inBearerTokenSignatureScope && !isTestFile(pass, x) {
					reportBearerTokenSignature(pass, x)
				}
			case *ast.AssignStmt:
				if inBearerTokenEncodingScope && !isTestFile(pass, x) {
					reportBearerTokenEncodeAssignments(pass, x.Lhs, x.Rhs)
				}
			case *ast.ValueSpec:
				if inBearerTokenEncodingScope && !isTestFile(pass, x) {
					lhs := make([]ast.Expr, 0, len(x.Names))
					for _, name := range x.Names {
						lhs = append(lhs, name)
					}
					reportBearerTokenEncodeAssignments(pass, lhs, x.Values)
				}
			case *ast.CallExpr:
				if inSecretSurfaceScope && isSecretStringConversion(x) {
					pass.Reportf(x.Pos(),
						"secret-bearing API/auth code must not convert secret bytes to string; keep material in []byte (AN-8)")
				}
				if inBearerTokenEncodingScope && !isTestFile(pass, x) && isBearerTokenStringConversion(x) {
					pass.Reportf(x.Pos(),
						"bearer-token code must not convert token bytes to string; keep material in []byte (AN-8)")
				}
				if inSignerAuthorizationTokenStringScope && !isTestFile(pass, x) && isSignerAuthorizationTokenStringConversion(x) {
					pass.Reportf(x.Pos(),
						"signer authorization-token code must not convert token bytes to string; keep material in []byte (AN-8)")
				}
				if inSignerAuthorizationTokenCommandScope && !isTestFile(pass, x) && isSignerAuthorizationTokenCommandDecodeString(x) {
					pass.Reportf(x.Pos(),
						"signer authorization-token command output must not be converted to string before decoding; use bytes.TrimSpace and base64.Decode (AN-8)")
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

func inspectWithParent(file *ast.File, fn func(ast.Node, ast.Node) bool) {
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		var parent ast.Node
		if len(stack) > 0 {
			parent = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return fn(n, parent)
	})
}

// providerCredentialConfigPkgs are non-provider packages that nonetheless declare
// provider-shaped credential fields. internal/config holds the operator-supplied
// INBOUND side of every provider credential (and the OIDC confidential-client
// secret), so a credential-named string field there is the same AN-8 leak as one
// in the provider package that later reads it — the string is minted at config
// load and outlives every byte-backed hop downstream.
//
// Scoped by exact package path, and only the credential-NAMED fields listed in
// providerCredentialNames are flagged, so the several hundred ordinary string
// knobs in internal/config (Issuer, Region, Endpoint, RedirectURI, ...) stay
// untouched. The //trstctl:keymaterial marker is deliberately NOT used for this
// package: it flags every string-backed field and would make the rule unusable
// here. Extending this set is a deliberate, reviewed change, with a fixture.
var providerCredentialConfigPkgs = map[string]bool{
	"trstctl.com/trstctl/internal/config": true,
}

func providerCredentialScope(pkg string) bool {
	return providerCredentialConfigPkgs[pkg] ||
		strings.HasPrefix(pkg, "trstctl.com/trstctl/internal/kms/") ||
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

func bearerTokenFieldName(field *ast.Field) bool {
	for _, name := range field.Names {
		if isBearerTokenName(name.Name) {
			return true
		}
	}
	return false
}

func reportBearerTokenStructFields(pass *analysis.Pass, spec *ast.TypeSpec) {
	st, ok := spec.Type.(*ast.StructType)
	if !ok || st.Fields == nil {
		return
	}
	for _, field := range st.Fields.List {
		if bearerTokenFieldName(field) && isStringBacked(pass, field.Type) {
			pass.Reportf(field.Type.Pos(),
				"bearer-token field must not use string; use []byte (AN-8)")
		}
	}
}

func reportBearerTokenSignature(pass *analysis.Pass, fn *ast.FuncDecl) {
	if fn.Type == nil {
		return
	}
	if fn.Type.Params != nil {
		for _, field := range fn.Type.Params.List {
			if bearerTokenFieldName(field) && isStringBacked(pass, field.Type) {
				pass.Reportf(field.Type.Pos(),
					"bearer-token parameter must not use string; use []byte (AN-8)")
			}
		}
	}
	if !bearerTokenMintFunction(fn.Name.Name) || fn.Type.Results == nil {
		return
	}
	for _, field := range fn.Type.Results.List {
		if isStringBacked(pass, field.Type) {
			pass.Reportf(field.Type.Pos(),
				"bearer-token function must not return string; use []byte (AN-8)")
		}
	}
}

func bearerTokenMintFunction(name string) bool {
	return strings.Contains(name, "Token") && !strings.Contains(strings.ToLower(name), "hash")
}

func reportBearerTokenEncodeAssignments(pass *analysis.Pass, lhs, rhs []ast.Expr) {
	if len(lhs) == 0 || len(rhs) == 0 {
		return
	}
	for i, expr := range rhs {
		if !tokenAssignmentTarget(lhs, i) {
			continue
		}
		call := findEncodeToStringCall(expr)
		if call == nil {
			continue
		}
		pass.Reportf(call.Pos(),
			"bearer-token code must not encode token bytes to string; use byte-backed encoders (AN-8)")
	}
}

func tokenAssignmentTarget(lhs []ast.Expr, rhsIndex int) bool {
	if len(lhs) == 1 {
		return isBearerTokenTarget(lhs[0])
	}
	if rhsIndex >= len(lhs) {
		return false
	}
	return isBearerTokenTarget(lhs[rhsIndex])
}

func isBearerTokenTarget(expr ast.Expr) bool {
	switch x := expr.(type) {
	case *ast.Ident:
		return isBearerTokenName(x.Name)
	case *ast.SelectorExpr:
		return isBearerTokenName(x.Sel.Name)
	default:
		return false
	}
}

func isBearerTokenStringConversion(call *ast.CallExpr) bool {
	if len(call.Args) != 1 {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	if !ok || id.Name != "string" {
		return false
	}
	return isBearerTokenExpr(call.Args[0])
}

func isBearerTokenExpr(expr ast.Expr) bool {
	switch x := expr.(type) {
	case *ast.Ident:
		return isBearerTokenName(x.Name)
	case *ast.SelectorExpr:
		return isBearerTokenName(x.Sel.Name)
	default:
		return false
	}
}

func isSignerAuthorizationTokenStringConversion(call *ast.CallExpr) bool {
	if len(call.Args) != 1 {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	if !ok || id.Name != "string" {
		return false
	}
	return isSignerAuthorizationTokenExpr(call.Args[0])
}

func isSignerAuthorizationTokenExpr(expr ast.Expr) bool {
	switch x := expr.(type) {
	case *ast.Ident:
		return isSignerAuthorizationTokenName(x.Name)
	case *ast.SelectorExpr:
		return isSignerAuthorizationTokenName(x.Sel.Name)
	default:
		return false
	}
}

func isSignerAuthorizationTokenName(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(name, "_", ""))
	return normalized == "token" ||
		strings.Contains(normalized, "signauthtoken") ||
		strings.Contains(normalized, "authorizationtoken") ||
		strings.Contains(normalized, "authtoken")
}

func isSignerAuthorizationTokenCommandDecodeString(call *ast.CallExpr) bool {
	if len(call.Args) != 1 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "DecodeString" {
		return false
	}
	return containsCommandOutputStringConversion(call.Args[0])
}

func containsCommandOutputStringConversion(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || id.Name != "string" {
			return true
		}
		arg, ok := call.Args[0].(*ast.Ident)
		if ok && isCommandOutputName(arg.Name) {
			found = true
			return false
		}
		return true
	})
	return found
}

func isCommandOutputName(name string) bool {
	normalized := strings.ToLower(name)
	return normalized == "out" || normalized == "output" || normalized == "stdout"
}

func findEncodeToStringCall(expr ast.Expr) *ast.CallExpr {
	var found *ast.CallExpr
	ast.Inspect(expr, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isEncodeToStringCall(call) {
			found = call
			return false
		}
		return true
	})
	return found
}

func isEncodeToStringCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "EncodeToString"
}

func isBearerTokenName(name string) bool {
	return name == "Token" || name == "token"
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
