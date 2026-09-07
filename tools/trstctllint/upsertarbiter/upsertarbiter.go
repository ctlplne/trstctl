// SPDX-License-Identifier: MPL-2.0

// Package upsertarbiter is the OPP-C01 guard for the DP2-043 / DP2-046 defect
// family: an INSERT ... ON CONFLICT upsert is race-safe only on its arbiter.
// When the target table carries a second unique index, Postgres's speculative
// insertion can still raise 23505 on that index while two identical inserts
// race — the arbiter never fires, and the tail apply surfaces as a 500. Every
// projection upsert into such a table must either serialize on an advisory
// lock (pg_advisory_xact_lock keyed on the arbiter) or retry on
// unique_violation. Pre-existing sites are listed in a reviewed baseline so a
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
	reComment     = regexp.MustCompile(`--[^\n]*`)
	reCreateTable = regexp.MustCompile(`(?is)CREATE TABLE (?:IF NOT EXISTS )?"?(\w+)"?\s*\((.*?)\);`)
	rePK          = regexp.MustCompile(`(?i)PRIMARY KEY\s*\(([^)]*)\)`)
	reUnique      = regexp.MustCompile(`(?i)(?:CONSTRAINT\s+(\w+)\s+)?UNIQUE\s*\(([^)]*)\)`)
	reInlineCol   = regexp.MustCompile(`(?i)^\s*"?(\w+)"?\s+\w[^,(]*?\b(PRIMARY KEY|UNIQUE)\b`)
	reUniqueIndex = regexp.MustCompile(`(?i)CREATE UNIQUE INDEX (?:CONCURRENTLY )?(?:IF NOT EXISTS )?"?(\w+)"?\s+ON\s+"?(\w+)"?\s*(?:USING \w+\s*)?\(([^)]*)\)`)
	reAddConstr   = regexp.MustCompile(`(?i)ALTER TABLE (?:ONLY )?"?(\w+)"?\s+ADD CONSTRAINT\s+"?(\w+)"?\s+(UNIQUE|PRIMARY KEY)\s*\(([^)]*)\)`)
)

var schemaCache sync.Map // migrations dir -> *schema

func (s *schema) add(table string, c colset) {
	if len(c) == 0 {
		return
	}
	for _, have := range s.unique[table] {
		if have.key() == c.key() {
			return
		}
	}
	s.unique[table] = append(s.unique[table], c)
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
	s := &schema{unique: map[string][]colset{}, named: map[string]colset{}}
	for _, m := range reCreateTable.FindAllStringSubmatch(sql, -1) {
		table, body := strings.ToLower(m[1]), m[2]
		for _, pk := range rePK.FindAllStringSubmatch(body, -1) {
			c := cols(pk[1])
			s.add(table, c)
			s.named[table+"_pkey"] = c
		}
		for _, u := range reUnique.FindAllStringSubmatch(body, -1) {
			c := cols(u[2])
			s.add(table, c)
			if u[1] != "" {
				s.named[strings.ToLower(u[1])] = c
			}
		}
		for _, line := range strings.Split(body, ",") {
			// table-level constraint clauses are not inline column definitions
			if first := strings.ToUpper(strings.Fields(strings.TrimSpace(line) + " x")[0]); first == "CONSTRAINT" || first == "PRIMARY" || first == "UNIQUE" || first == "FOREIGN" || first == "CHECK" || first == "EXCLUDE" {
				continue
			}
			if im := reInlineCol.FindStringSubmatch(line); im != nil {
				c := cols(im[1])
				s.add(table, c)
				if strings.EqualFold(im[2], "PRIMARY KEY") {
					s.named[table+"_pkey"] = c
				}
			}
		}
	}
	for _, m := range reUniqueIndex.FindAllStringSubmatch(sql, -1) {
		c := cols(m[3])
		s.add(strings.ToLower(m[2]), c)
		s.named[strings.ToLower(m[1])] = c
	}
	for _, m := range reAddConstr.FindAllStringSubmatch(sql, -1) {
		table, c := strings.ToLower(m[1]), cols(m[4])
		s.add(table, c)
		s.named[strings.ToLower(m[2])] = c
		if strings.EqualFold(m[3], "PRIMARY KEY") {
			s.named[table+"_pkey"] = c
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
	var walk func(n ast.Node) bool
	walk = func(n ast.Node) bool {
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
var guardMarkers = []string{"pg_advisory_xact_lock", "23505", "UniqueViolation", "unique_violation"}

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
				var uncovered []string
				for _, u := range uniques {
					if u.key() != arb.key() {
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
	pkgs, err := parser.ParseDir(fset, abs, func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
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
	for _, p := range pkgs {
		for _, f := range p.Files {
			files = append(files, f)
		}
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
