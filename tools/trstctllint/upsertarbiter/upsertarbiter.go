// SPDX-License-Identifier: MPL-2.0

// Package upsertarbiter is the OPP-C01 guard for the DP2-043 / DP2-046 defect
// family: an INSERT ... ON CONFLICT upsert is race-safe only on its arbiter.
// When the target table carries a second unique index, Postgres's speculative
// insertion can still raise 23505 on that index while two identical inserts
// race — the arbiter never fires, and the tail apply surfaces as a 500. Every
// projection upsert that can repeat a second unique key must serialize on an advisory
// lock (pg_advisory_xact_lock keyed on the arbiter) or retry on
// unique_violation. An explicit fresh UUID on a secondary key does not repeat
// that key; defaults and caller-supplied IDs receive no such exemption.
// Pre-existing sites are listed in a reviewed baseline so a
// NEW site fails closed; the baseline is pinned so it cannot go stale.
package upsertarbiter

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/tools/go/analysis"
)

var Analyzer = &analysis.Analyzer{
	Name: "upsertarbiter",
	Doc:  "OPP-C01: an ON CONFLICT upsert into a table with a second unique index must serialize (pg_advisory_xact_lock) or retry on unique_violation (23505); a concurrent identical insert can otherwise raise 23505 on the non-arbiter index (DP2-043/DP2-046).",
	Run:  run,
}

// Site is one INSERT ... ON CONFLICT upsert whose table carries a unique index
// other than the arbiter's, together with whether the enclosing function (or a
// same-package function it calls) mitigates the race.
type Site struct {
	File      string   // repo-relative when resolvable, else the parsed path
	Func      string   // enclosing function name
	Table     string   // upsert target
	Arbiter   []string // ON CONFLICT columns (resolved through ON CONSTRAINT names)
	Uncovered []string // one uncovered unique set per entry, rendered as "a,b"
	Guarded   bool     // advisory lock or 23505/unique-violation handling present
	Baselined bool     // listed in the reviewed baseline
	Pos       token.Pos
}

// ---- schema ----

type schema struct {
	unique map[string][]colset // table -> unique column sets
	named  map[string]colset   // constraint/index name -> columns (incl. <table>_pkey)
	owners map[string]owner    // constraint/index name -> the unique set it enforces
}

type colset []string

func (c colset) key() string { return strings.Join(c, ",") }

func cols(s string) colset {
	var out colset
	for _, p := range strings.Split(s, ",") {
		p = strings.ToLower(strings.Trim(strings.TrimSpace(p), `"`))
		if p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

var (
	reComment      = regexp.MustCompile(`--[^\n]*`)
	reCreateTable  = regexp.MustCompile(`(?is)^CREATE TABLE (?:IF NOT EXISTS )?"?(\w+)"?\s*\((.*)\)\s*$`)
	rePK           = regexp.MustCompile(`(?i)PRIMARY KEY\s*\(([^)]*)\)`)
	reUnique       = regexp.MustCompile(`(?i)(?:CONSTRAINT\s+(\w+)\s+)?UNIQUE\s*\(([^)]*)\)`)
	reInlineCol    = regexp.MustCompile(`(?i)^\s*"?(\w+)"?\s+\w[^,(]*?\b(PRIMARY KEY|UNIQUE)\b`)
	reUniqueIndex  = regexp.MustCompile(`(?is)^CREATE UNIQUE INDEX (?:CONCURRENTLY )?(?:IF NOT EXISTS )?"?(\w+)"?\s+ON\s+(?:ONLY\s+)?"?(\w+)"?\s*(?:USING \w+\s*)?\(([^)]*)\)`)
	reAlterTable   = regexp.MustCompile(`(?is)^ALTER TABLE (?:ONLY )?(?:IF EXISTS )?"?(\w+)"?\s+(.*)$`)
	reActAddConstr = regexp.MustCompile(`(?is)^ADD CONSTRAINT\s+"?(\w+)"?\s+(UNIQUE|PRIMARY KEY)\s*\(([^)]*)\)`)
	reActAddBare   = regexp.MustCompile(`(?is)^ADD (UNIQUE|PRIMARY KEY)\s*\(([^)]*)\)`)
	reActUsingIdx  = regexp.MustCompile(`(?is)^ADD CONSTRAINT\s+"?(\w+)"?\s+(UNIQUE|PRIMARY KEY)\s+USING INDEX\s+"?(\w+)"?`)
	reActDrop      = regexp.MustCompile(`(?is)^DROP CONSTRAINT\s+(?:IF EXISTS\s+)?"?(\w+)"?`)
	reDropIndex    = regexp.MustCompile(`(?is)^DROP INDEX\s+(?:CONCURRENTLY\s+)?(?:IF EXISTS\s+)?"?(\w+)"?`)
)

var schemaCache sync.Map // migrations dir -> *schema

// owner records which table a named constraint or index belongs to and the
// unique column set it enforces, so a later DROP can retire exactly that set.
type owner struct {
	table string
	cols  colset
}

// add registers a unique column set under a constraint or index name. The same
// set may be enforced by several names (a UNIQUE constraint plus the primary key
// re-pinned onto the same index); it stays live until the last owner is dropped.
func (s *schema) add(table, name string, c colset) {
	if len(c) == 0 {
		return
	}
	name = strings.ToLower(name)
	if name != "" {
		s.owners[name] = owner{table: table, cols: c}
		s.named[name] = c
	}
	for _, have := range s.unique[table] {
		if have.key() == c.key() {
			return
		}
	}
	s.unique[table] = append(s.unique[table], c)
}

// drop retires the unique set a constraint or index name enforced, unless another
// live name still enforces the same set on the same table.
func (s *schema) drop(name string) {
	name = strings.ToLower(name)
	o, ok := s.owners[name]
	if !ok {
		return
	}
	delete(s.owners, name)
	delete(s.named, name)
	for _, other := range s.owners {
		if other.table == o.table && other.cols.key() == o.cols.key() {
			return
		}
	}
	kept := s.unique[o.table][:0]
	for _, have := range s.unique[o.table] {
		if have.key() != o.cols.key() {
			kept = append(kept, have)
		}
	}
	s.unique[o.table] = kept
}

// defaultKeyName mirrors PostgreSQL's generated name for an unnamed UNIQUE
// constraint (<table>_<col>_..._key), which is what a later DROP CONSTRAINT names.
func defaultKeyName(table string, c colset) string {
	return table + "_" + strings.Join(c, "_") + "_key"
}

// splitStatements cuts the migration stream at top-level semicolons, honouring
// parentheses and single-quoted strings, so DDL is applied in migration order.
func splitStatements(sql string) []string {
	var out []string
	var b strings.Builder
	depth, quoted := 0, false
	for _, r := range sql {
		switch {
		case r == '\'':
			quoted = !quoted
		case quoted:
		case r == '(':
			depth++
		case r == ')':
			if depth > 0 {
				depth--
			}
		case r == ';' && depth == 0:
			if stmt := strings.TrimSpace(b.String()); stmt != "" {
				out = append(out, stmt)
			}
			b.Reset()
			continue
		}
		b.WriteRune(r)
	}
	if stmt := strings.TrimSpace(b.String()); stmt != "" {
		out = append(out, stmt)
	}
	return out
}

// splitActions cuts one ALTER TABLE statement's action list at top-level commas.
func splitActions(actions string) []string {
	var out []string
	var b strings.Builder
	depth := 0
	for _, r := range actions {
		switch r {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(b.String()))
				b.Reset()
				continue
			}
		}
		b.WriteRune(r)
	}
	if a := strings.TrimSpace(b.String()); a != "" {
		out = append(out, a)
	}
	return out
}

func (s *schema) applyCreateTable(table, body string) {
	for _, pk := range rePK.FindAllStringSubmatch(body, -1) {
		s.add(table, table+"_pkey", cols(pk[1]))
	}
	for _, u := range reUnique.FindAllStringSubmatch(body, -1) {
		c := cols(u[2])
		name := strings.ToLower(u[1])
		if name == "" {
			name = defaultKeyName(table, c)
		}
		s.add(table, name, c)
	}
	for _, line := range splitActions(body) {
		// table-level constraint clauses are not inline column definitions
		if first := strings.ToUpper(strings.Fields(line + " x")[0]); first == "CONSTRAINT" || first == "PRIMARY" || first == "UNIQUE" || first == "FOREIGN" || first == "CHECK" || first == "EXCLUDE" {
			continue
		}
		if im := reInlineCol.FindStringSubmatch(line); im != nil {
			c := cols(im[1])
			if strings.EqualFold(im[2], "PRIMARY KEY") {
				s.add(table, table+"_pkey", c)
			} else {
				s.add(table, defaultKeyName(table, c), c)
			}
		}
	}
}

func (s *schema) applyAlterTable(table, actions string) {
	for _, act := range splitActions(actions) {
		switch {
		case reActUsingIdx.MatchString(act):
			m := reActUsingIdx.FindStringSubmatch(act)
			if o, ok := s.owners[strings.ToLower(m[3])]; ok {
				s.add(table, m[1], o.cols)
				if strings.EqualFold(m[2], "PRIMARY KEY") {
					s.add(table, table+"_pkey", o.cols)
				}
			}
		case reActAddConstr.MatchString(act):
			m := reActAddConstr.FindStringSubmatch(act)
			c := cols(m[3])
			s.add(table, m[1], c)
			if strings.EqualFold(m[2], "PRIMARY KEY") {
				s.add(table, table+"_pkey", c)
			}
		case reActAddBare.MatchString(act):
			m := reActAddBare.FindStringSubmatch(act)
			c := cols(m[2])
			if strings.EqualFold(m[1], "PRIMARY KEY") {
				s.add(table, table+"_pkey", c)
			} else {
				s.add(table, defaultKeyName(table, c), c)
			}
		case reActDrop.MatchString(act):
			s.drop(reActDrop.FindStringSubmatch(act)[1])
		}
	}
}

func loadSchema(migrationsDir string) (*schema, error) {
	if v, ok := schemaCache.Load(migrationsDir); ok {
		return v.(*schema), nil
	}
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		raw, readErr := os.ReadFile(filepath.Join(migrationsDir, n)) // #nosec G304 -- migration files under the repository store package (CWE-22)
		if readErr != nil {
			return nil, readErr
		}
		b.Write(raw)
		b.WriteString("\n")
	}
	sql := reComment.ReplaceAllString(b.String(), "")
	s := &schema{unique: map[string][]colset{}, named: map[string]colset{}, owners: map[string]owner{}}
	// Statements are applied in migration order: a unique set is live from the
	// CREATE/ADD that introduces it until the DROP that retires it, so a primary
	// key moved onto other columns or a dropped index no longer counts as a
	// second arbiter-less index.
	for _, stmt := range splitStatements(sql) {
		switch {
		case reCreateTable.MatchString(stmt):
			m := reCreateTable.FindStringSubmatch(stmt)
			s.applyCreateTable(strings.ToLower(m[1]), m[2])
		case reUniqueIndex.MatchString(stmt):
			m := reUniqueIndex.FindStringSubmatch(stmt)
			s.add(strings.ToLower(m[2]), m[1], cols(m[3]))
		case reAlterTable.MatchString(stmt):
			m := reAlterTable.FindStringSubmatch(stmt)
			s.applyAlterTable(strings.ToLower(m[1]), m[2])
		case reDropIndex.MatchString(stmt):
			s.drop(reDropIndex.FindStringSubmatch(stmt)[1])
		}
	}
	schemaCache.Store(migrationsDir, s)
	return s, nil
}

// migrationsFor locates the store package's migrations directory from a source
// file path: the file's own directory (internal/store and the testdata mirror
// both keep migrations/ beside the Go files), else internal/store/migrations
// found by walking up.
func migrationsFor(file string) string {
	dir := filepath.Dir(file)
	if st, err := os.Stat(filepath.Join(dir, "migrations")); err == nil && st.IsDir() {
		return filepath.Join(dir, "migrations")
	}
	for d := dir; d != filepath.Dir(d); d = filepath.Dir(d) {
		cand := filepath.Join(d, "internal", "store", "migrations")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
	}
	return ""
}

// ---- SQL sites ----

var reUpsert = regexp.MustCompile(`(?is)INSERT\s+INTO\s+"?(\w+)"?.*?ON\s+CONFLICT\s*(?:\(([^)]*)\)|ON\s+CONSTRAINT\s+"?(\w+)"?|(DO\s+NOTHING))`)

type literalUnit struct {
	text string
	pos  token.Pos
}

// literalUnits returns every string-literal unit in fn's body in source order;
// a `+`-concatenated chain of string literals is one unit, so SQL split across
// lines with + still parses as one statement.
func literalUnits(fn *ast.FuncDecl) []literalUnit {
	var units []literalUnit
	walk := func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.BinaryExpr:
			if e.Op == token.ADD {
				if text, ok := concatString(e); ok {
					units = append(units, literalUnit{text: text, pos: e.Pos()})
					return false
				}
			}
		case *ast.BasicLit:
			if e.Kind == token.STRING {
				if v, err := strconv.Unquote(e.Value); err == nil {
					units = append(units, literalUnit{text: v, pos: e.Pos()})
				}
			}
		}
		return true
	}
	if fn.Body != nil {
		ast.Inspect(fn.Body, walk)
	}
	return units
}

func concatString(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(x.Value)
		return v, err == nil
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, okl := concatString(x.X)
		r, okr := concatString(x.Y)
		return l + r, okl && okr
	case *ast.ParenExpr:
		return concatString(x.X)
	}
	return "", false
}

// guardMarkers are the mitigations the rule accepts inside the enclosing
// function or a same-package function it calls: an advisory lock serializing
// the upsert, or explicit unique-violation handling (retry / classification).
var guardMarkers = []string{"23505", "UniqueViolation", "unique_violation"}

// Shared backup/lifecycle locks admit concurrent writers; their longer name
// must not satisfy the exclusive serialization requirement by substring.
var exclusiveLockCall = regexp.MustCompile(`(?i)\bpg_advisory_xact_lock\s*\(`)

func bodyHasGuard(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch e := n.(type) {
		case *ast.BasicLit:
			if e.Kind == token.STRING {
				if sql, err := strconv.Unquote(e.Value); err == nil && exclusiveLockCall.MatchString(sql) {
					found = true
				}
				for _, m := range guardMarkers {
					if strings.Contains(e.Value, m) {
						found = true
					}
				}
			}
		case *ast.Ident:
			for _, m := range guardMarkers {
				if strings.Contains(e.Name, m) {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

func calleeNames(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	if fn.Body == nil {
		return out
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			out[f.Name] = true
		case *ast.SelectorExpr:
			out[f.Sel.Name] = true
		}
		return true
	})
	return out
}

func guarded(fn *ast.FuncDecl, decls map[string][]*ast.FuncDecl) bool {
	if bodyHasGuard(fn) {
		return true
	}
	for name := range calleeNames(fn) {
		for _, d := range decls[name] {
			if d != fn && bodyHasGuard(d) {
				return true
			}
		}
	}
	return false
}

func funcName(fn *ast.FuncDecl) string {
	if fn.Name == nil {
		return ""
	}
	return fn.Name.Name
}

// scanFiles applies the rule to parsed files sharing one schema.
func scanFiles(files []*ast.File, fset *token.FileSet, sch *schema, relName func(token.Pos) string) []Site {
	decls := map[string][]*ast.FuncDecl{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Name != nil {
				decls[fn.Name.Name] = append(decls[fn.Name.Name], fn)
			}
		}
	}
	var sites []Site
	for _, f := range files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			for _, unit := range literalUnits(fn) {
				m := reUpsert.FindStringSubmatchIndex(unit.text)
				if m == nil {
					continue
				}
				text := unit.text
				table := strings.ToLower(text[m[2]:m[3]])
				var arb colset
				switch {
				case m[8] >= 0: // target-less DO NOTHING absorbs every unique violation
					continue
				case m[4] >= 0:
					arb = cols(text[m[4]:m[5]])
				case m[6] >= 0:
					name := strings.ToLower(text[m[6]:m[7]])
					c, known := sch.named[name]
					if !known {
						continue
					}
					arb = c
				}
				uniques, known := sch.unique[table]
				if !known || len(arb) == 0 {
					continue
				}
				fresh := freshInsertColumns(text)
				var uncovered []string
				for _, u := range uniques {
					if u.key() != arb.key() && !hasFreshColumn(u, fresh) {
						uncovered = append(uncovered, u.key())
					}
				}
				if len(uncovered) == 0 {
					continue
				}
				sites = append(sites, Site{
					File: relName(unit.pos), Func: funcName(fn), Table: table, Arbiter: arb, Uncovered: uncovered,
					Guarded: guarded(fn, decls), Pos: unit.pos,
				})
			}
		}
	}
	return sites
}

// ---- analyzer ----

func run(pass *analysis.Pass) (interface{}, error) {
	if len(pass.Files) == 0 {
		return nil, nil
	}
	first := pass.Fset.Position(pass.Files[0].Pos()).Filename
	// Scope: the repository package that owns the migrations (and its testdata
	// mirror). The baseline is keyed to internal/store; activating on every
	// package that can reach the schema would surface unreviewed sites elsewhere.
	if !inStorePackage(pass.Fset, pass.Files[0].Pos()) {
		return nil, nil
	}
	migrations := migrationsFor(first)
	if migrations == "" {
		return nil, nil // not a repository package with a schema beside it: rule inactive
	}
	sch, err := loadSchema(migrations)
	if err != nil {
		return nil, nil
	}
	rel := func(pos token.Pos) string { return normalizedFilename(pass.Fset, pos) }
	for _, site := range scanFiles(pass.Files, pass.Fset, sch, rel) {
		if site.Guarded || reviewedUse(site.File, site.Func, reviewedUpserts) {
			continue
		}
		pass.Reportf(site.Pos,
			"upsert on %s arbitrates on (%s) but the table also has unique (%s): a concurrent identical insert can raise 23505 on the second index (OPP-C01, DP2-043/DP2-046); serialize with pg_advisory_xact_lock keyed on the arbiter or retry on unique_violation, or add a reviewed baseline entry in upsertarbiter",
			site.Table, strings.Join(site.Arbiter, ","), strings.Join(site.Uncovered, "; "))
	}
	return nil, nil
}

func normalizedFilename(fset *token.FileSet, pos token.Pos) string {
	name := filepath.ToSlash(fset.Position(pos).Filename)
	if i := strings.Index(name, "/trstctl.com/trstctl/"); i >= 0 {
		return name[i+len("/trstctl.com/trstctl/"):]
	}
	return strings.TrimPrefix(name, "./")
}

func reviewedUse(file, fn string, allow map[string]map[string]bool) bool {
	for suffix, funcs := range allow {
		if strings.HasSuffix(file, suffix) && funcs[fn] {
			return true
		}
	}
	return false
}

// ---- exported scanner for in-package invariant tests ----

// ScanDir parses every non-test Go file in dir against dir/migrations and
// returns each upsert site whose table carries a second unique index, with
// Guarded and Baselined resolved. File is the path relative to the repository
// root when dir sits under one, so it matches the baseline keys.
func ScanDir(dir string) ([]Site, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	migrations := migrationsFor(filepath.Join(abs, "x.go"))
	if migrations == "" {
		return nil, fmt.Errorf("no migrations directory beside %s", abs)
	}
	sch, err := loadSchema(migrations)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(abs)
	if err != nil {
		return nil, err
	}
	root := repoRoot(abs)
	rel := func(pos token.Pos) string {
		name := fset.Position(pos).Filename
		if root != "" {
			if r, relErr := filepath.Rel(root, name); relErr == nil {
				return filepath.ToSlash(r)
			}
		}
		return filepath.ToSlash(name)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, parseErr := parser.ParseFile(fset, filepath.Join(abs, name), nil, 0)
		if parseErr != nil {
			return nil, parseErr
		}
		files = append(files, f)
	}
	sort.Slice(files, func(i, j int) bool {
		return fset.Position(files[i].Pos()).Filename < fset.Position(files[j].Pos()).Filename
	})
	sites := scanFiles(files, fset, sch, rel)
	for i := range sites {
		sites[i].Baselined = reviewedUse(sites[i].File, sites[i].Func, reviewedUpserts)
	}
	return sites, nil
}

func repoRoot(dir string) string {
	for d := dir; d != filepath.Dir(d); d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
	}
	return ""
}

// ReviewedBaseline returns a copy of the reviewed pre-existing sites
// (repo-relative file -> function names) so tests can pin that none is stale.
func ReviewedBaseline() map[string][]string {
	out := map[string][]string{}
	for file, funcs := range reviewedUpserts {
		for fn := range funcs {
			out[file] = append(out[file], fn)
		}
		sort.Strings(out[file])
	}
	return out
}

// inStorePackage reports whether pos lies in internal/store, whether the driver
// hands us a repo-relative path (analysistest) or an absolute worktree path
// (go vet -vettool).
func inStorePackage(fset *token.FileSet, pos token.Pos) bool {
	if strings.HasPrefix(normalizedFilename(fset, pos), "internal/store/") {
		return true
	}
	return strings.Contains("/"+filepath.ToSlash(fset.Position(pos).Filename), "/internal/store/")
}
