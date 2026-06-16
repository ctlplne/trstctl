// Package directive detects trstctl marker comments such as
// //trstctl:keymaterial, //trstctl:repository, and //trstctl:mutation.
//
// Markers are opt-in: they make a rule stricter for the annotated package or
// function. They are NOT a suppression mechanism — there is deliberately no way
// to silence a finding with a comment (see the linter README). Matching is on
// the whole comment line so that incidental prose mentioning a marker never
// triggers a rule.
package directive

import (
	"go/ast"
	"strings"
)

// Present reports whether any file in the package carries the given marker
// (for example "trstctl:keymaterial") as a standalone line comment.
func Present(files []*ast.File, marker string) bool {
	for _, f := range files {
		for _, group := range f.Comments {
			for _, c := range group.List {
				if matches(c.Text, marker) {
					return true
				}
			}
		}
	}
	return false
}

// OnFunc reports whether a function's doc comment carries the given marker.
func OnFunc(fn *ast.FuncDecl, marker string) bool {
	if fn == nil || fn.Doc == nil {
		return false
	}
	for _, c := range fn.Doc.List {
		if matches(c.Text, marker) {
			return true
		}
	}
	return false
}

// matches reports whether a single comment is exactly the marker, tolerating an
// optional space after the slashes ("//m" or "// m"). Exact equality (rather
// than substring) keeps explanatory prose from accidentally activating a rule.
func matches(commentText, marker string) bool {
	return strings.TrimSpace(strings.TrimPrefix(commentText, "//")) == marker
}
