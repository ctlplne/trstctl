// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/events"
)

// A newly declared key-state event must not silently enter ingress as a
// shared-mode event while its projection requires exclusive key custody.
func TestKeyStateIngressClassCoversDeclaredMutationEventsCR045(t *testing.T) {
	for _, source := range []string{"projections.go", "deployment_kek.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			group, ok := declaration.(*ast.GenDecl)
			if !ok || group.Tok != token.CONST {
				continue
			}
			for _, spec := range group.Specs {
				values := spec.(*ast.ValueSpec)
				for index, name := range values.Names {
					if name.Name != "EventTenantOffboarded" &&
						!strings.HasPrefix(name.Name, "EventTenantKeyDomain") &&
						!strings.HasPrefix(name.Name, "EventDeploymentKEKRotation") {
						continue
					}
					if index >= len(values.Values) {
						t.Fatalf("%s: %s has no explicit event type", source, name.Name)
					}
					literal, ok := values.Values[index].(*ast.BasicLit)
					if !ok || literal.Kind != token.STRING {
						t.Fatalf("%s: %s has no string event type", source, name.Name)
					}
					eventType, err := strconv.Unquote(literal.Value)
					if err != nil {
						t.Fatal(err)
					}
					if !events.RequiresExclusiveKeyStateAdmission(eventType) {
						t.Errorf("%s: %s (%s) lacks exclusive ingress admission", source, name.Name, eventType)
					}
				}
			}
		}
	}
	for _, public := range []string{"tenant.registered", "secret.sync.queued"} {
		if events.RequiresExclusiveKeyStateAdmission(public) {
			t.Errorf("ordinary %s classified as exclusive key-state mutation", public)
		}
	}
}
