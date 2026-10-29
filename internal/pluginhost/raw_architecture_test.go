// SPDX-License-Identifier: BUSL-1.1
package pluginhost

import (
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Check selectors rather than only calls: taking a method value must not turn
// the private loader into a new admission path. The compiler separately guards
// callers outside this package.
func rawAdmissionViolations(name string, source []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), name, source, parser.ParseComments)
	if err != nil {
		return []string{err.Error()}
	}
	var violations []string
	allowed := map[string]map[string]bool{
		"instantiateUnverified": {"provenance.go:LoadVerified": true, "provenance.go:LoadVerifiedWithProvenance": true, "conformance.go:conformanceUnderGrant": true, "conformance_exports.go:Load": true},
		"conformance":           {"conformance_exports.go:Conformance": true},
		"conformanceUnderGrant": {"conformance.go:conformance": true, "conformance_exports.go:ConformanceUnderGrant": true},
	}
	public := map[string]bool{"Load": true, "Conformance": true, "ConformanceUnderGrant": true}
	tagged := false
	for _, group := range f.Comments {
		for _, comment := range group.List {
			if strings.HasPrefix(comment.Text, "//go:build ") {
				expr, parseErr := constraint.Parse(comment.Text)
				// Exactly this expression; an OR with a production tag must not qualify.
				tagged = parseErr == nil && expr.String() == "trstctl_conformance" && comment.Pos() < f.Package
			}
		}
	}
	for _, declaration := range f.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if ok && public[fn.Name.Name] && fn.Recv != nil && (name != "conformance_exports.go" || !tagged) {
			violations = append(violations, "public raw method outside exact conformance tag: "+fn.Name.Name)
		}
		owner := ""
		if ok {
			owner = fn.Name.Name
		}
		ast.Inspect(declaration, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if ok {
				if sites, guarded := allowed[selector.Sel.Name]; guarded && !sites[name+":"+owner] {
					violations = append(violations, fmt.Sprintf("unapproved raw selector %s in %s:%s", selector.Sel.Name, name, owner))
				}
			}
			return true
		})
	}
	return violations
}

func TestPrivateRawAdmissionStaysInsideVerifiedAndConformancePaths(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name) // #nosec G304 -- enumerated Go source in this package only (CWE-22).
		if err != nil {
			t.Fatal(err)
		}
		for _, violation := range rawAdmissionViolations(name, source) {
			t.Error(violation)
		}
	}
}

func TestRawAdmissionGuardRejectsMethodValuesAndProductionTags(t *testing.T) {
	for _, source := range []string{
		"package pluginhost; func escape(h *Host){ _ = h.instantiateUnverified }",
		"//go:build trstctl_conformance || trstctl_core\n\npackage pluginhost; func(h *Host) Load(){}",
		"package pluginhost; var escape = (*Host).conformanceUnderGrant",
	} {
		if len(rawAdmissionViolations("conformance_exports.go", []byte(source))) == 0 {
			t.Fatalf("guard accepted %s", source)
		}
	}
	good := "//go:build trstctl_conformance\n\npackage pluginhost; func(h *Host) Load(){ h.instantiateUnverified() }"
	if got := rawAdmissionViolations("conformance_exports.go", []byte(good)); len(got) != 0 {
		t.Fatalf("valid facade refused: %v", got)
	}
}
