// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// A266: PostgreSQL resolves a bare ORDER BY name against the select list's
// output columns before the table's. A select list that casts the keyset
// column without an alias (id::text, the shape every row scanner here reads)
// names an output column "id", so "ORDER BY id" sorted every page of the
// table by the text form instead of riding the primary key: each 50-row page
// of the certificate inventory became a parallel sequential scan and top-N
// sort of the whole table (35 ms at 102,000 rows against 0.25 ms qualified),
// and every full-inventory iteration (risk, graph, revocation health, the
// weak-key audit) grew with the square of the inventory. Every keyset page
// in this package must order by the qualified table column.
func TestKeysetPagesOrderByTheTableColumn(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	type sourceFile struct {
		name string
		file *ast.File
	}
	var parsed []sourceFile
	consts := map[string]string{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(name) // #nosec G304 -- the package's own source files (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, raw, 0)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, sourceFile{name, f})
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, ident := range vs.Names {
					if i < len(vs.Values) {
						if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							if v, err := strconv.Unquote(lit.Value); err == nil {
								consts[ident.Name] = v
							}
						}
					}
				}
			}
		}
	}
	// sqlOf rebuilds a string expression: literals and package string
	// constants joined with +; anything else (a computed clause) becomes a
	// neutral placeholder.
	var sqlOf func(ast.Expr) (string, bool)
	sqlOf = func(e ast.Expr) (string, bool) {
		switch v := e.(type) {
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				return "", false
			}
			s, err := strconv.Unquote(v.Value)
			return s, err == nil
		case *ast.Ident:
			s, ok := consts[v.Name]
			return s, ok
		case *ast.BinaryExpr:
			if v.Op != token.ADD {
				return "", false
			}
			l, lok := sqlOf(v.X)
			r, rok := sqlOf(v.Y)
			if !lok && !rok {
				return "", false
			}
			if !lok {
				l = " "
			}
			if !rok {
				r = " "
			}
			return l + r, true
		case *ast.ParenExpr:
			return sqlOf(v.X)
		}
		return "", false
	}
	keyset := regexp.MustCompile(`(?i)\b(?:[a-z_][a-z0-9_]*\.)?([a-z_][a-z0-9_]*) > \$\d+`)
	selectList := regexp.MustCompile(`(?is)^\s*select\s+(?:distinct\s+)?(.*?)\bfrom\b`)
	orderBy := regexp.MustCompile(`(?is)\border by\s+(.+?)(?:\blimit\b|$)`)
	var violations []string
	for _, sf := range parsed {
		ast.Inspect(sf.file, func(n ast.Node) bool {
			expr, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			if _, isBinary := expr.(*ast.BinaryExpr); !isBinary {
				if _, isLit := expr.(*ast.BasicLit); !isLit {
					return true
				}
			}
			sql, ok := sqlOf(expr)
			if !ok || !strings.Contains(strings.ToUpper(sql), "ORDER BY") {
				return true
			}
			flat := strings.Join(strings.Fields(sql), " ")
			k := keyset.FindStringSubmatch(flat)
			sel := selectList.FindStringSubmatch(flat)
			ob := orderBy.FindStringSubmatch(flat)
			if k == nil || sel == nil || ob == nil {
				return true
			}
			column := strings.ToLower(k[1])
			first := strings.ToLower(strings.TrimSpace(strings.Split(ob[1], ",")[0]))
			first = strings.Fields(first + " ")[0]
			casts := regexp.MustCompile(`(?i)(?:^|[\s,(])` + regexp.QuoteMeta(column) + `::[a-z_\[\]]+(?:\s*(?:,|$))`)
			lastKey := strings.ToLower(strings.TrimSpace(ob[1]))
			if (first == column || strings.Contains(lastKey, ", "+column)) && casts.MatchString(sel[1]) {
				violations = append(violations, fset.Position(expr.Pos()).String()+": "+flat[:min(len(flat), 160)])
			}
			return false
		})
	}
	if len(violations) > 0 {
		t.Fatalf("keyset pages order by a column their select list casts (PostgreSQL sorts by the cast output, not the table column; qualify it as table.column):\n  %s",
			strings.Join(violations, "\n  "))
	}
}
