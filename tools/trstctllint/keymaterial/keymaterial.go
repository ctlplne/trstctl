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

// Analyzer enforces AN-8.
var Analyzer = &analysis.Analyzer{
	Name: "keymaterial",
	Doc:  "AN-8: key-handling packages (secret/seal by default, or //trstctl:keymaterial) must not use string for key material; use []byte.",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	if !inScope(pass) {
		return nil, nil
	}
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			field, ok := n.(*ast.Field)
			if !ok {
				return true
			}
			if isStringBacked(pass, field.Type) {
				pass.Reportf(field.Type.Pos(),
					"key-handling package must not use string for key material; use []byte (AN-8)")
			}
			return true
		})
	}
	return nil, nil
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
