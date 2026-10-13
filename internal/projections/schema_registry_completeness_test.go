// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"

	"trstctl.com/trstctl/internal/events"
)

func schemaEventName(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		if base, ok := value.X.(*ast.Ident); ok {
			return base.Name + "." + value.Sel.Name
		}
	}
	return ""
}

// The switch is the source of truth for events decoded by this projector.
// A missing version entry would let a future payload shape reach the old decoder.
func TestEveryCoreProjectedEventHasSchemaVersionRegistration(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "projections.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	registered := make(map[string]bool)
	for _, decl := range file.Decls {
		general, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range general.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || value.Names[0].Name != "knownSchemaVersions" || len(value.Values) != 1 {
				continue
			}
			literal, ok := value.Values[0].(*ast.CompositeLit)
			if !ok {
				t.Fatal("knownSchemaVersions is no longer a map literal; update this guard")
			}
			for _, element := range literal.Elts {
				entry, ok := element.(*ast.KeyValueExpr)
				if !ok {
					t.Fatal("unexpected knownSchemaVersions entry")
				}
				registered[schemaEventName(entry.Key)] = true
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, target := range assignment.Lhs {
			indexed, ok := target.(*ast.IndexExpr)
			if !ok {
				continue
			}
			if base, ok := indexed.X.(*ast.Ident); ok && base.Name == "knownSchemaVersions" {
				registered[schemaEventName(indexed.Index)] = true
			}
		}
		return true
	})
	var core *ast.FuncDecl
	for _, decl := range file.Decls {
		if function, ok := decl.(*ast.FuncDecl); ok && function.Name.Name == "applyCoreEventTx" {
			core = function
			break
		}
	}
	if core == nil {
		t.Fatal("applyCoreEventTx missing; update this guard")
	}
	projected := make(map[string]bool)
	ast.Inspect(core.Body, func(node ast.Node) bool {
		sw, ok := node.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		tag, ok := sw.Tag.(*ast.SelectorExpr)
		if !ok || tag.Sel.Name != "Type" {
			return true
		}
		if base, ok := tag.X.(*ast.Ident); !ok || base.Name != "e" {
			return true
		}
		for _, clause := range sw.Body.List {
			for _, expr := range clause.(*ast.CaseClause).List {
				name := schemaEventName(expr)
				if name == "" {
					t.Fatalf("projected event has a non-static case: %T", expr)
				}
				projected[name] = true
			}
		}
		return false
	})
	if len(projected) == 0 || len(registered) == 0 {
		t.Fatal("projector switch or version registry missing; update this guard")
	}
	missing := make([]string, 0)
	for name := range projected {
		if !registered[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		t.Errorf("projected event %s has no schema-version registration", name)
	}
}

func TestProfileEditApprovalRejectsUnknownSchemaVersion(t *testing.T) {
	for _, eventType := range []string{
		EventProfileEditApprovalRequested,
		EventProfileEditApprovalApproved,
		EventProfileEditApprovalRefused,
	} {
		event := events.Event{Type: eventType, SchemaVersion: 2}
		if err := ValidateSchemaVersion(event); !errors.Is(err, ErrUnknownSchemaVersion) {
			t.Errorf("%s v2: got %v, want ErrUnknownSchemaVersion", eventType, err)
		}
	}
}
