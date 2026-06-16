// Package eventsource implements the AN-2 architecture rule: a served mutating
// handler must not write the relational read model directly. State changes are
// emitted as events to the append-only log (the source of truth); the read
// model is a projection of that log. A handler that writes the read model
// directly bypasses the log, so the audit trail and a rebuild-from-log cannot
// reproduce the change.
//
// A handler opts into the served-mutation surface with the //trstctl:mutation
// marker (the same marker AN-5 uses — these are the same handlers). Inside such a
// handler, BOTH of these are a violation:
//
//   - a call to a Create/Update/Delete/Upsert/Set method on *store.Store (a
//     read-model mutator), resolved by TYPE so it cannot be evaded by aliasing;
//   - a RAW SQL statement (INSERT INTO / UPDATE / DELETE FROM) targeting a
//     read-model table (owners, issuers, identities, certificates, tenants,
//     identity_transitions) — the SPINE-010 evasion: a handler that reaches past
//     the store mutators and runs `tx.Exec("INSERT INTO owners ...")` would have
//     slipped through the call-name check. The SQL string is judged by shape so a
//     bare "DELETE" method token or a struct literal is not mistaken for SQL.
//
// The handler must instead emit a domain event and let the projection build the
// read model. Reads (Get*/List*/Exists*; SELECT) are unaffected.
//
// The rule is scoped to the served mutation surface. The projector — the one
// sanctioned writer of the read model — is not a mutation handler, so it is not
// constrained here; nor are migrations or rebuild helpers.
package eventsource

import (
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"

	"trstctl.com/trstctl/tools/trstctllint/internal/directive"
)

const (
	mutationMarker = "trstctl:mutation"
	storePkgPath   = "trstctl.com/trstctl/internal/store"
	storeTypeName  = "Store"
)

// mutatorPrefixes name the store methods that write the relational read model.
// Read methods (Get/List/Exists/Lookup) and event helpers are not listed, so
// they remain available to handlers.
var mutatorPrefixes = []string{"Create", "Update", "Delete", "Upsert", "Set"}

// readModelTables are the relational tables that are pure projections of the
// event log (store.ReadModelTables). A //trstctl:mutation handler must never
// write them with raw SQL — it must emit an event. Keep this in sync with
// internal/store.ReadModelTables; a table joins this set as it becomes
// event-sourced.
var readModelTables = []string{
	"owners", "issuers", "identities", "certificates", "tenants", "identity_transitions",
}

// Analyzer enforces AN-2.
var Analyzer = &analysis.Analyzer{
	Name: "eventsource",
	Doc:  "AN-2: a //trstctl:mutation handler must not write the read model directly (store mutator OR raw SQL); it must emit an event.",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !directive.OnFunc(fn, mutationMarker) {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				// (1) Store read-model mutator call (resolved by type).
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && isMutatorName(sel.Sel.Name) {
						if isStoreReceiver(pass, sel.X) {
							pass.Reportf(call.Pos(),
								"served mutation must not write the read model directly via store.%s; emit an event and project it (AN-2)",
								sel.Sel.Name)
						}
					}
				}
				// (2) Raw SQL write of a read-model table (SPINE-010): a string
				// literal that is an INSERT/UPDATE/DELETE against a projected table.
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if s, err := strconv.Unquote(lit.Value); err == nil {
						if tbl, bad := rawReadModelWrite(s); bad {
							pass.Reportf(lit.Pos(),
								"served mutation must not write the read model table %q with raw SQL; emit an event and project it (AN-2)",
								tbl)
						}
					}
				}
				return true
			})
		}
	}
	return nil, nil
}

// rawReadModelWrite reports whether s is an INSERT/UPDATE/DELETE statement whose
// target is a read-model table, and which table. It is strict about statement
// SHAPE (INSERT INTO / UPDATE <t> SET / DELETE FROM) so a bare HTTP-method token
// ("DELETE") or a struct-literal fragment is not mistaken for SQL, mirroring the
// tenantfilter rule. A SELECT is never a write, so it is ignored.
func rawReadModelWrite(s string) (string, bool) {
	lower := strings.ToLower(s)
	fields := strings.Fields(lower)
	if len(fields) < 2 {
		return "", false
	}
	var target string
	switch fields[0] {
	case "insert":
		if fields[1] != "into" || len(fields) < 3 {
			return "", false
		}
		target = stripQual(fields[2])
	case "delete":
		if fields[1] != "from" || len(fields) < 3 {
			return "", false
		}
		target = stripQual(fields[2])
	case "update":
		// UPDATE <table> SET ...; require a SET clause so a struct field named
		// "update" is not mistaken for SQL.
		if !strings.Contains(lower, " set ") {
			return "", false
		}
		target = stripQual(fields[1])
	default:
		return "", false
	}
	for _, t := range readModelTables {
		if target == t {
			return t, true
		}
	}
	return "", false
}

// stripQual trims a schema qualifier and any trailing punctuation from a table
// token, so "public.owners," and "owners(" both reduce to "owners".
func stripQual(tok string) string {
	tok = strings.TrimRight(tok, "(),;")
	if i := strings.LastIndex(tok, "."); i >= 0 {
		tok = tok[i+1:]
	}
	return tok
}

// isStoreReceiver reports whether expr has type *store.Store (the read-model
// repository). Resolution is by type, so it cannot be evaded by aliasing the
// receiver's name.
func isStoreReceiver(pass *analysis.Pass, expr ast.Expr) bool {
	tv, ok := pass.TypesInfo.Types[expr]
	if !ok {
		return false
	}
	ptr, ok := tv.Type.(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := ptr.Elem().(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Name() == storeTypeName &&
		obj.Pkg() != nil && obj.Pkg().Path() == storePkgPath
}

// isMutatorName reports whether a method name writes the read model: it begins
// with a mutator verb and the remainder is empty or starts a new word (an
// uppercase letter), so "Settings" would not match "Set".
func isMutatorName(name string) bool {
	for _, p := range mutatorPrefixes {
		if !strings.HasPrefix(name, p) {
			continue
		}
		rest := name[len(p):]
		if rest == "" || (rest[0] >= 'A' && rest[0] <= 'Z') {
			return true
		}
	}
	return false
}
