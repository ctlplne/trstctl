// Package tenantfilter implements the AN-1 architecture rule: data-manipulation
// SQL queries in repository-layer packages must FILTER on tenant_id, so
// multi-tenant isolation cannot be bypassed by a forgotten predicate.
//
// What "filter on tenant_id" means (ARCH-003/SEC-004/TENANT-001). The earlier
// revision accepted any query whose text merely CONTAINED the substring
// "tenant_id" — so a cross-tenant query that only SELECTs tenant_id, casts it
// (tenant_id::text), or names it in a trailing comment passed CI. This rule is
// now clause-aware: it strips SQL comments first and then requires tenant_id in
// a PREDICATE position:
//
//   - SELECT / UPDATE / DELETE: tenant_id must appear in a WHERE clause or a
//     JOIN ... ON condition. A SELECT-list / RETURNING / ORDER BY / type-cast
//     mention does not count.
//   - INSERT: tenant_id must appear in the inserted column list, or in an
//     ON CONFLICT (...) conflict-target / WITH CHECK — i.e. the written row is
//     constrained to a tenant.
//
// Package scope (ARCH-003 blind spot). Repository packages are those under
// internal/store, those carrying the //trstctl:repository marker, AND any
// package that imports internal/store and runs raw DML against tenant tables
// (e.g. the orchestrator outbox / idempotency, the idempotency GC). This closes
// the hole where tenant-data SQL outside internal/store was never inspected.
//
// Sanctioned exemptions are the same escape-hatch philosophy as before — fixed
// in one auditable place with a fixture, never a per-line ignore:
//
//   - system (non-tenant) tables such as the migration ledger (systemTables);
//   - session/lock control functions that read no table (sessionControlFuncs);
//   - a statement carrying the //trstctl:system-query line comment: a
//     DELIBERATE cross-tenant system operation (an auth-by-secret lookup whose
//     tenant is not yet known, a cross-tenant dispatcher/GC). The marker makes
//     the intent explicit and greppable; it is the only way to exempt a real
//     DML statement, and it must sit on the statement's own comment.
package tenantfilter

import (
	"go/ast"
	"go/token"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"

	"trstctl.com/trstctl/tools/trstctllint/internal/directive"
)

const (
	modulePath       = "trstctl.com/trstctl"
	repositoryPkg    = modulePath + "/internal/store"
	repositoryMarker = "trstctl:repository"
	// systemQueryMarker exempts a single DML statement that is a deliberate
	// cross-tenant system operation. It must appear as a standalone line comment
	// on (immediately above, or trailing) the statement's string literal.
	systemQueryMarker = "trstctl:system-query"
)

// defaultRepositoryPkgs are the packages OUTSIDE internal/store that mix
// per-tenant DML with raw system DML against tenant tables, and so must be
// inspected even though they are not under internal/store — the ARCH-003 blind
// spot, named in the audit as "orchestrator outbox SQL on raw Store.Pool()".
// They are in scope whether or not they carry the //trstctl:repository marker,
// so the AN-1 rule on their raw tenant-data SQL is fail-closed: a forgotten or
// deleted marker cannot silently turn enforcement off there (ARCH-004
// fail-open). The marker remains available to bring further repository-like
// packages into scope; extending this default set is a deliberate, reviewed
// change here, with a fixture.
//
// The set is intentionally narrow. It does NOT include:
//   - layers that merely import the store (the API router, projections,
//     servers), which hold no raw tenant DML and would only add false positives;
//   - the pure cross-tenant maintenance sweepers (internal/idemgc,
//     internal/outboxgc), which by construction contain ONLY system-wide
//     retention queries (no per-tenant access path to protect) and are
//     documented as living outside the repository layer. Should one ever gain a
//     per-tenant query, the //trstctl:repository marker brings it into scope.
var defaultRepositoryPkgs = map[string]bool{
	modulePath + "/internal/orchestrator": true,
}

// Analyzer enforces AN-1.
var Analyzer = &analysis.Analyzer{
	Name: "tenantfilter",
	Doc:  "AN-1: SQL data-manipulation queries in repository packages must filter on tenant_id (in a WHERE/ON-CONFLICT/INSERT-column predicate, not merely mention it).",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	if !isRepositoryPackage(pass) {
		return nil, nil
	}
	exempt := systemQueryLines(pass)
	for _, file := range pass.Files {
		// The rule guards shipped repository code, not test helpers, which
		// deliberately run system-role / RLS-bypassing raw SQL (redelivery
		// simulators, cross-tenant RLS probes). Skip _test.go files.
		if isTestFile(pass, file) {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			// Evaluate each whole SQL expression once. A query built by
			// concatenation ("DELETE FROM " + table + " WHERE tenant_id=$1")
			// is judged as a unit, so a leading fragment is not flagged for
			// lacking a predicate that lives in a later fragment. Visiting at
			// the concatenation root (and not descending) also avoids
			// double-reporting the inner literals.
			expr, ok := sqlExpr(n)
			if !ok {
				return true
			}
			sql, ok := joinedSQL(expr)
			if !ok {
				return true
			}
			clean := stripSQLComments(sql)
			if !isDML(clean) {
				return true
			}
			if referencesSystemTable(clean) || isSessionControl(clean) {
				return false
			}
			if exempt[pass.Fset.Position(expr.Pos()).Line] {
				return false // explicit //trstctl:system-query exemption
			}
			if !filtersOnTenant(clean) {
				pass.Reportf(expr.Pos(),
					"repository query does not filter on tenant_id in a WHERE/ON-CONFLICT/INSERT-column predicate (AN-1)")
			}
			return false
		})
	}
	return nil, nil
}

// sqlExpr returns the expression to evaluate as a SQL statement: a string
// concatenation rooted at a binary + expression, or a bare string literal that
// is not itself part of a larger concatenation (those are handled at the root).
// The second return is false for any other node.
func sqlExpr(n ast.Node) (ast.Expr, bool) {
	switch e := n.(type) {
	case *ast.BinaryExpr:
		if e.Op == token.ADD && isStringConcat(e) {
			return e, true
		}
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			return e, true
		}
	}
	return nil, false
}

// isStringConcat reports whether a + expression is a concatenation that includes
// at least one string literal (so it is plausibly a built SQL string), as
// opposed to numeric addition.
func isStringConcat(e *ast.BinaryExpr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			found = true
			return false
		}
		return true
	})
	return found
}

// joinedSQL flattens a string-literal concatenation into one SQL string,
// replacing every non-literal operand (an interpolated identifier such as a
// table name from a vetted constant) with a single space so token boundaries
// survive. It returns ok=false if the expression contains no string literal.
func joinedSQL(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(e.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		left, lok := operandSQL(e.X)
		right, rok := operandSQL(e.Y)
		if !lok && !rok {
			return "", false
		}
		return left + right, true
	}
	return "", false
}

// operandSQL renders one operand of a concatenation: a string literal as its
// value, a nested concatenation recursively, and anything else (an identifier,
// call, etc.) as a single space placeholder.
func operandSQL(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			if s, err := strconv.Unquote(e.Value); err == nil {
				return s, true
			}
		}
		return " ", false
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			if s, ok := joinedSQL(e); ok {
				return s, true
			}
		}
		return " ", false
	default:
		return " ", false
	}
}

// isTestFile reports whether the file is a _test.go file.
func isTestFile(pass *analysis.Pass, file *ast.File) bool {
	name := pass.Fset.Position(file.Pos()).Filename
	return strings.HasSuffix(name, "_test.go")
}

// isRepositoryPackage reports whether the package is part of the repository
// layer: by location (internal/store), by the //trstctl:repository marker, or
// by being one of the default-on raw-DML packages outside the store (ARCH-003
// blind spot, fail-closed). The store package and its subpackages always
// qualify.
func isRepositoryPackage(pass *analysis.Pass) bool {
	p := pass.Pkg.Path()
	if p == repositoryPkg || strings.HasPrefix(p, repositoryPkg+"/") {
		return true
	}
	if defaultRepositoryPkgs[p] {
		return true
	}
	return directive.Present(pass.Files, repositoryMarker)
}

// systemQueryLines returns the set of source lines carrying the
// //trstctl:system-query marker, so a deliberate cross-tenant statement on (or
// just below) such a line is exempt. The marker is matched on a whole comment
// line, never as a substring, so incidental prose cannot exempt a query.
func systemQueryLines(pass *analysis.Pass) map[int]bool {
	lines := map[int]bool{}
	for _, file := range pass.Files {
		for _, group := range file.Comments {
			for _, c := range group.List {
				if !isSystemQueryComment(c.Text) {
					continue
				}
				// Exempt the comment's own line and the immediately following
				// line, so the marker may sit on or just above the statement.
				ln := pass.Fset.Position(c.Pos()).Line
				lines[ln] = true
				lines[ln+1] = true
			}
		}
	}
	return lines
}

// isSystemQueryComment reports whether a comment is the system-query marker. The
// marker must be the FIRST token of the comment (after the // and optional
// space), optionally followed by whitespace and an explanatory justification —
// e.g. "//trstctl:system-query — auth runs before any tenant is known". It is
// matched as a whole leading token, never a substring, so prose that merely
// mentions the marker mid-sentence ("// avoid the trstctl:system-query hatch")
// does not exempt a query.
func isSystemQueryComment(commentText string) bool {
	body := strings.TrimSpace(strings.TrimPrefix(commentText, "//"))
	if body == systemQueryMarker {
		return true
	}
	rest := strings.TrimPrefix(body, systemQueryMarker)
	if rest == body {
		return false // does not start with the marker
	}
	// The marker must be followed by whitespace (a separator before the
	// justification), not by more identifier characters (which would make it a
	// different, longer marker token).
	r := rest[0]
	return r == ' ' || r == '\t'
}

// isDML reports whether a string is a SQL data-manipulation statement. It is
// deliberately strict about statement SHAPE so that a bare HTTP-method token
// ("DELETE", "GET") or a struct-literal fragment is NOT mistaken for SQL (the
// rule now scopes over packages — the API router, CLI — that hold such strings):
//
//   - SELECT must be followed (eventually) by FROM or be a function select
//     (SELECT count(*), SELECT set_config(...));
//   - INSERT must be "INSERT INTO";
//   - UPDATE must have a SET clause;
//   - DELETE must be "DELETE FROM".
//
// DDL (CREATE/ALTER/TRUNCATE) is intentionally out of scope.
func isDML(s string) bool {
	lower := strings.ToLower(s)
	fields := strings.Fields(lower)
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "select":
		// A real SELECT reads FROM a table or calls a function; a lone
		// "SELECT" or "select your meal..." prose does not.
		return strings.Contains(lower, " from ") || strings.Contains(lower, "(")
	case "insert":
		return len(fields) >= 2 && fields[1] == "into"
	case "update":
		return strings.Contains(lower, " set ")
	case "delete":
		return len(fields) >= 2 && fields[1] == "from"
	default:
		return false
	}
}

// filtersOnTenant reports whether a DML statement constrains rows to a tenant:
// for INSERT, tenant_id is among the inserted columns or the conflict target;
// for SELECT/UPDATE/DELETE, tenant_id appears in a WHERE or JOIN..ON predicate.
func filtersOnTenant(sql string) bool {
	lower := strings.ToLower(sql)
	fields := strings.Fields(lower)
	if len(fields) == 0 {
		return false
	}
	if fields[0] == "insert" {
		return insertConstrainsTenant(lower)
	}
	return predicateMentionsTenant(lower)
}

// tenantColRe matches tenant_id as a whole column identifier (so it does not
// match a substring like other_tenant_idx). It permits an optional table/alias
// qualifier (a.tenant_id) and tolerates a type cast (tenant_id::text).
var tenantColRe = regexp.MustCompile(`(?:[a-z_][a-z0-9_]*\.)?\btenant_id\b`)

// predicateMentionsTenant reports whether tenant_id appears in a row-restricting
// predicate: the WHERE clause or a JOIN ... ON condition. Other positions
// (SELECT list, RETURNING, ORDER BY, GROUP BY) do not count.
func predicateMentionsTenant(lower string) bool {
	for _, region := range predicateRegions(lower) {
		if tenantColRe.MatchString(region) {
			return true
		}
	}
	return false
}

// clauseTerminators end a WHERE/ON predicate region; tenant_id appearing only
// after one of these (e.g. ORDER BY tenant_id) is not a filter.
var clauseTerminators = []string{
	" group by ", " order by ", " limit ", " offset ",
	" returning ", " for update", " for share", " window ",
	" union ", " intersect ", " except ", " on conflict ",
}

// predicateRegions extracts the text of each WHERE clause and each JOIN..ON
// condition in the statement, trimmed at the next clause terminator. Multiple
// regions arise from subqueries and multiple joins; tenant_id in ANY of them
// satisfies the rule (a subquery may carry the tenant predicate).
func predicateRegions(lower string) []string {
	var regions []string
	regions = append(regions, clauseBodies(lower, " where ")...)
	regions = append(regions, clauseBodies(lower, " on ")...)
	return regions
}

// clauseBodies returns, for each occurrence of the keyword, the substring from
// just after the keyword up to the next clause terminator (or end of string).
func clauseBodies(lower, keyword string) []string {
	var out []string
	search := lower
	base := 0
	for {
		idx := strings.Index(search, keyword)
		if idx < 0 {
			break
		}
		start := base + idx + len(keyword)
		body := lower[start:]
		if end := nextTerminator(body); end >= 0 {
			body = body[:end]
		}
		out = append(out, body)
		base = start
		search = lower[base:]
	}
	return out
}

// nextTerminator returns the index in body of the earliest clause terminator,
// or -1 if none is present.
func nextTerminator(body string) int {
	best := -1
	for _, t := range clauseTerminators {
		if i := strings.Index(body, t); i >= 0 && (best < 0 || i < best) {
			best = i
		}
	}
	return best
}

// insertConstrainsTenant reports whether an INSERT writes tenant_id: either
// tenant_id is in the inserted column list (the parenthesized list before
// VALUES / SELECT), or it is part of an ON CONFLICT (...) conflict target (an
// upsert keyed in part on the tenant).
func insertConstrainsTenant(lower string) bool {
	if cols, ok := insertColumnList(lower); ok && tenantColRe.MatchString(cols) {
		return true
	}
	if target, ok := conflictTarget(lower); ok && tenantColRe.MatchString(target) {
		return true
	}
	return false
}

// insertColumnList returns the text inside the first parenthesized list that
// follows "insert into <table>" and precedes VALUES/SELECT/ON. An INSERT without
// an explicit column list (rare here) yields ok=false.
func insertColumnList(lower string) (string, bool) {
	const kw = "insert into "
	i := strings.Index(lower, kw)
	if i < 0 {
		return "", false
	}
	rest := lower[i+len(kw):]
	open := strings.Index(rest, "(")
	if open < 0 {
		return "", false
	}
	// Guard against picking up the VALUES(...) list: the column list's open
	// paren must come before the first VALUES / SELECT keyword.
	if v := firstKeywordIndex(rest, " values", " select", " default values"); v >= 0 && v < open {
		return "", false
	}
	close := matchingParen(rest, open)
	if close < 0 {
		return "", false
	}
	return rest[open+1 : close], true
}

// conflictTarget returns the text inside the parentheses of an
// "on conflict (...)" clause, if present.
func conflictTarget(lower string) (string, bool) {
	const kw = "on conflict"
	i := strings.Index(lower, kw)
	if i < 0 {
		return "", false
	}
	rest := lower[i+len(kw):]
	open := strings.Index(rest, "(")
	if open < 0 {
		return "", false // ON CONFLICT DO NOTHING with no target
	}
	close := matchingParen(rest, open)
	if close < 0 {
		return "", false
	}
	return rest[open+1 : close], true
}

// matchingParen returns the index of the parenthesis that closes the one at
// open, accounting for nesting, or -1 if unbalanced.
func matchingParen(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// firstKeywordIndex returns the earliest index at which any of the keywords
// occurs in s, or -1.
func firstKeywordIndex(s string, keywords ...string) int {
	best := -1
	for _, k := range keywords {
		if i := strings.Index(s, k); i >= 0 && (best < 0 || i < best) {
			best = i
		}
	}
	return best
}

// stripSQLComments removes -- line comments and /* block */ comments so that a
// tenant_id mentioned only in a comment cannot satisfy the rule. Newlines are
// preserved as spaces so token boundaries survive.
func stripSQLComments(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		// Line comment: -- ... to end of line.
		if s[i] == '-' && i+1 < len(s) && s[i+1] == '-' {
			j := i + 2
			for j < len(s) && s[j] != '\n' {
				j++
			}
			b.WriteByte(' ')
			i = j
			continue
		}
		// Block comment: /* ... */ (non-nested, which is enough for our SQL).
		if s[i] == '/' && i+1 < len(s) && s[i+1] == '*' {
			j := i + 2
			for j+1 < len(s) && !(s[j] == '*' && s[j+1] == '/') {
				j++
			}
			b.WriteByte(' ')
			if j+1 < len(s) {
				i = j + 2
			} else {
				i = len(s)
			}
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// systemTables are non-tenant, infrastructure tables that legitimately carry no
// tenant_id (e.g. the migration ledger). This is the sanctioned escape hatch —
// a fix to the rule itself, not a per-line ignore — and is extended only here,
// with a test fixture.
var systemTables = []string{
	"schema_migrations",
	// projection_checkpoint is the single-row global read-model high-water mark
	// (SPINE-007): the event-stream sequence is global and monotonic, so the
	// watermark is one number for the whole deployment, not per tenant. It is
	// owned by the system role and never read under a tenant RLS context, like
	// schema_migrations.
	"projection_checkpoint",
}

// referencesSystemTable reports whether a query targets a known system table.
func referencesSystemTable(s string) bool {
	lower := strings.ToLower(s)
	for _, tbl := range systemTables {
		if strings.Contains(lower, tbl) {
			return true
		}
	}
	return false
}

// sessionControlFuncs are PostgreSQL control functions that operate on the
// session or on cluster-wide locks, not on tenant rows: a `SELECT
// pg_advisory_lock(...)` reads no table and so carries no tenant_id. Like
// systemTables, this is the sanctioned escape hatch — extended only here, with a
// test fixture.
var sessionControlFuncs = []string{
	"pg_advisory_lock",
	"pg_advisory_unlock",
	"pg_try_advisory_lock",
	"pg_advisory_xact_lock",
	// set_config / current_setting drive the RLS session variable
	// (trstctl.tenant_id) and the role; they configure the session, not a
	// tenant table. WithTenant itself issues `SELECT set_config(...)`.
	"set_config",
	"current_setting",
	// to_regclass is a system-catalog existence check (used by the migrator),
	// not a tenant-table read.
	"to_regclass",
}

// isSessionControl reports whether a query is a session/lock control call rather
// than a data query over a table.
func isSessionControl(s string) bool {
	lower := strings.ToLower(s)
	for _, fn := range sessionControlFuncs {
		if strings.Contains(lower, fn) {
			return true
		}
	}
	return false
}
