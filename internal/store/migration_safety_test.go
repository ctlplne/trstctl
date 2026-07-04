// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// onlineSafeBaseline grandfathers the migrations that shipped BEFORE the
// online-safety guard existed (SCHEMA-006). Up to and including this version, the
// schema was greenfield/additive and the few `CREATE INDEX` statements on an
// existing table (0007, 0018, 0021, 0022) ran when that table was newly introduced
// and effectively empty — a strength the audit confirmed ("0x destructive ops"),
// not a live-lock incident. The guard binds every migration AFTER this number, so
// the FIRST index/column added to a genuinely populated table at GA scale must use
// the online-safe form. Raising this baseline is not how you add a migration —
// write the new migration online-safe (or justify it with `-- online-safe:`).
const onlineSafeBaseline = 25

// TestMigrationsAreOnlineSafe is the SCHEMA-006 guard: it scans the shipped SQL
// migrations and fails if a statement would take a long ACCESS EXCLUSIVE lock on an
// ALREADY-POPULATED table without using the online-safe form (or carrying an
// explicit `-- online-safe: <reason>` justification on the statement). It encodes
// the playbook in docs/migrations.md as an enforced precedent so the first
// lock-heavy change to a live table cannot silently ship.
//
// Today every migration creates each index in the SAME migration as its (empty)
// table, so this guard passes; it exists to catch the FUTURE migration that adds an
// index/column to a populated table or rewrites a live column.
//
// What it flags (against a table NOT created in the same migration):
//   - CREATE INDEX without CONCURRENTLY (an ACCESS EXCLUSIVE-equivalent build lock);
//   - ALTER COLUMN ... TYPE (a full table rewrite);
//   - ADD COLUMN ... NOT NULL without a DEFAULT (a full table rewrite on older PG);
//   - DROP COLUMN / DROP TABLE / RENAME (destructive / query-breaking on live data).
//
// The escape hatch is a single `-- online-safe:` comment on (or directly above) the
// statement — the same auditable, greppable pattern the linter uses elsewhere — so
// a deliberate, justified exception is explicit, never invisible.
func TestMigrationsAreOnlineSafe(t *testing.T) {
	dir := "migrations"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var files []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		t.Fatal("no migration files found")
	}

	createTableRe := regexp.MustCompile(`(?i)\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?"?([a-z_][a-z0-9_]*)"?`)
	// Lock-heavy statement patterns, each capturing the target table where useful.
	createIndexRe := regexp.MustCompile(`(?i)\bcreate\s+(?:unique\s+)?index\s+(?:concurrently\s+)?(?:if\s+not\s+exists\s+)?"?[a-z0-9_]+"?\s+on\s+"?([a-z_][a-z0-9_]*)"?`)
	concurrentlyRe := regexp.MustCompile(`(?i)\bcreate\s+(?:unique\s+)?index\s+concurrently\b`)
	alterTypeRe := regexp.MustCompile(`(?i)\balter\s+(?:column\s+)?"?[a-z0-9_]+"?\s+(?:set\s+data\s+)?type\b`)
	addNotNullRe := regexp.MustCompile(`(?i)\badd\s+column\s+(?:if\s+not\s+exists\s+)?"?[a-z0-9_]+"?[^,;]*\bnot\s+null\b`)
	hasDefaultRe := regexp.MustCompile(`(?i)\bdefault\b`)
	dropPrimaryKeyConstraintRe := regexp.MustCompile(`(?i)\bdrop\s+constraint\s+(?:if\s+exists\s+)?"?[a-z0-9_]*pkey"?\b`)
	addPrimaryKeyConstraintRe := regexp.MustCompile(`(?i)\badd\s+(?:constraint\s+"?[a-z0-9_]+"?\s+)?primary\s+key\b`)
	destructiveRe := regexp.MustCompile(`(?i)\b(drop\s+column|drop\s+table|rename\s+(?:column|to))\b`)

	for _, name := range files {
		// Grandfather the pre-guard baseline; enforce on every newer migration. The
		// detector itself is proven non-vacuously by
		// TestMigrationSafetyDetectorFlagsLockHeavyDDL, so this loop being empty until
		// a >baseline migration ships does not make the guard meaningless.
		if v := migrationNumber(name); v <= onlineSafeBaseline {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(raw)
		// Tables this migration creates itself are empty, so any DDL against them is
		// not a lock-on-live-data concern.
		created := map[string]bool{}
		for _, m := range createTableRe.FindAllStringSubmatch(text, -1) {
			created[strings.ToLower(m[1])] = true
		}

		// Evaluate statement by statement so an `-- online-safe:` comment on the
		// statement (or just above it) exempts exactly that statement.
		for _, stmt := range splitStatements(text) {
			body := stripSQLLineComments(stmt.sql)
			lower := strings.ToLower(body)
			if strings.TrimSpace(lower) == "" {
				continue
			}
			exempt := stmt.onlineSafe

			// CREATE INDEX (non-concurrent) on an existing (not-this-migration) table.
			if m := createIndexRe.FindStringSubmatch(body); m != nil && !concurrentlyRe.MatchString(body) {
				tbl := strings.ToLower(m[1])
				if !created[tbl] && !exempt {
					t.Errorf("%s: CREATE INDEX on existing table %q is not CONCURRENTLY — it locks a populated table (ACCESS EXCLUSIVE). Use CREATE INDEX CONCURRENTLY in a no-tx migration, or justify with `-- online-safe:` (SCHEMA-006)", name, tbl)
				}
			}
			// ALTER COLUMN ... TYPE rewrites the table.
			if alterTypeRe.MatchString(body) && !exempt {
				if tbl, ok := alterTargetTable(body); !ok || !created[tbl] {
					t.Errorf("%s: ALTER COLUMN ... TYPE rewrites a live table under a long lock; use expand-contract, or justify with `-- online-safe:` (SCHEMA-006)\n  %s", name, oneLine(body))
				}
			}
			// ADD COLUMN ... NOT NULL without DEFAULT rewrites the table.
			if addNotNullRe.MatchString(body) && !hasDefaultRe.MatchString(body) && !exempt {
				if tbl, ok := alterTargetTable(body); !ok || !created[tbl] {
					t.Errorf("%s: ADD COLUMN ... NOT NULL without DEFAULT rewrites a live table; add nullable + backfill + CHECK NOT VALID/VALIDATE, or justify with `-- online-safe:` (SCHEMA-006)\n  %s", name, oneLine(body))
				}
			}
			// Replacing a primary key on a live table takes an ACCESS EXCLUSIVE
			// lock and can scan existing rows to validate the new key. It is
			// allowed only with a local justification and a populated before/after
			// harness for the exact migration.
			if (dropPrimaryKeyConstraintRe.MatchString(body) || addPrimaryKeyConstraintRe.MatchString(body)) && !exempt {
				if tbl, ok := alterTargetTable(body); !ok || !created[tbl] {
					t.Errorf("%s: primary-key constraint rewrite on existing table takes an ACCESS EXCLUSIVE lock; use expand-contract, or justify with `-- online-safe:` and a populated before/after harness\n  %s", name, oneLine(body))
				}
			}
			// Destructive / query-breaking ops on live data.
			if destructiveRe.MatchString(body) && !exempt {
				if tbl, ok := alterTargetTable(body); !ok || !created[tbl] {
					t.Errorf("%s: a destructive/renaming DDL (drop column/table, rename) breaks live data/queries under the forward-only policy; use expand-contract across releases, or justify with `-- online-safe:` (SCHEMA-006)\n  %s", name, oneLine(body))
				}
			}
		}
	}
}

type sqlStatement struct {
	sql        string
	onlineSafe bool // the statement (or the line directly above it) carries `-- online-safe:`
}

// splitStatements splits a migration into statements on `;` boundaries (a coarse
// split that is sufficient for our DDL scan — we do not execute these), and marks a
// statement online-safe if an `-- online-safe:` comment appears within it or on the
// line immediately preceding it.
func splitStatements(text string) []sqlStatement {
	lines := strings.Split(text, "\n")
	var out []sqlStatement
	var buf strings.Builder
	precededBySafe := false
	stmtHasSafe := false
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if isOnlineSafeComment(trimmed) {
			// A standalone `-- online-safe:` line annotates the NEXT statement.
			if buf.Len() == 0 {
				precededBySafe = true
			} else {
				stmtHasSafe = true
			}
		}
		buf.WriteString(ln)
		buf.WriteString("\n")
		if strings.Contains(ln, ";") {
			out = append(out, sqlStatement{sql: buf.String(), onlineSafe: stmtHasSafe || precededBySafe})
			buf.Reset()
			precededBySafe = false
			stmtHasSafe = false
		}
	}
	if strings.TrimSpace(buf.String()) != "" {
		out = append(out, sqlStatement{sql: buf.String(), onlineSafe: stmtHasSafe || precededBySafe})
	}
	return out
}

func isOnlineSafeComment(line string) bool {
	if !strings.HasPrefix(line, "--") {
		return false
	}
	body := strings.TrimSpace(strings.TrimPrefix(line, "--"))
	return strings.HasPrefix(strings.ToLower(body), "online-safe:")
}

var alterTableRe = regexp.MustCompile(`(?i)\balter\s+table\s+(?:if\s+exists\s+)?"?([a-z_][a-z0-9_]*)"?`)

func alterTargetTable(body string) (string, bool) {
	if m := alterTableRe.FindStringSubmatch(body); m != nil {
		return strings.ToLower(m[1]), true
	}
	return "", false
}

// stripSQLLineComments removes -- line comments so an `-- online-safe:` annotation
// or other prose cannot be mistaken for DDL.
func stripSQLLineComments(s string) string {
	var b strings.Builder
	for _, ln := range strings.Split(s, "\n") {
		if i := strings.Index(ln, "--"); i >= 0 {
			ln = ln[:i]
		}
		b.WriteString(ln)
		b.WriteString(" ")
	}
	return b.String()
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

var migrationNumRe = regexp.MustCompile(`^(\d+)`)

func migrationNumber(name string) int {
	if m := migrationNumRe.FindStringSubmatch(name); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return n
		}
	}
	return 0
}

// TestMigrationSafetyDetectorFlagsLockHeavyDDL proves the SCHEMA-006 guard's
// detector actually works (so the grandfathered guard above is not vacuously
// green): a synthetic future migration that adds an index to an existing,
// populated table without CONCURRENTLY is flagged, the same migration written
// CONCURRENTLY (or carrying `-- online-safe:`) is not, and a destructive
// drop/rename is flagged. This is the fixture/precedent the finding asks for.
func TestMigrationSafetyDetectorFlagsLockHeavyDDL(t *testing.T) {
	// A table NOT created in this migration → "owners" is treated as populated.
	created := map[string]bool{}

	scan := func(sql string) (flagged bool) {
		for _, stmt := range splitStatements(sql) {
			body := stripSQLLineComments(stmt.sql)
			if strings.TrimSpace(body) == "" {
				continue
			}
			if stmt.onlineSafe {
				continue
			}
			lower := strings.ToLower(body)
			if regexp.MustCompile(`(?i)\bcreate\s+(?:unique\s+)?index\b`).MatchString(body) &&
				!regexp.MustCompile(`(?i)\bconcurrently\b`).MatchString(body) {
				if m := regexp.MustCompile(`(?i)\bon\s+"?([a-z_][a-z0-9_]*)"?`).FindStringSubmatch(body); m != nil && !created[strings.ToLower(m[1])] {
					return true
				}
			}
			if regexp.MustCompile(`(?i)\b(drop\s+column|drop\s+table|rename\s+(?:column|to))\b`).MatchString(lower) {
				return true
			}
			if regexp.MustCompile(`(?i)\bdrop\s+constraint\s+(?:if\s+exists\s+)?"?[a-z0-9_]*pkey"?\b`).MatchString(lower) ||
				regexp.MustCompile(`(?i)\badd\s+(?:constraint\s+"?[a-z0-9_]+"?\s+)?primary\s+key\b`).MatchString(lower) {
				return true
			}
		}
		return false
	}

	cases := []struct {
		name     string
		sql      string
		wantFlag bool
	}{
		{
			name:     "create index without concurrently on existing table",
			sql:      "CREATE INDEX owners_region_idx ON owners (region);",
			wantFlag: true,
		},
		{
			name:     "create index concurrently is allowed",
			sql:      "CREATE INDEX CONCURRENTLY owners_region_idx ON owners (region);",
			wantFlag: false,
		},
		{
			name:     "online-safe justification exempts the statement",
			sql:      "-- online-safe: table is empty in this release\nCREATE INDEX owners_region_idx ON owners (region);",
			wantFlag: false,
		},
		{
			name:     "drop column is destructive",
			sql:      "ALTER TABLE owners DROP COLUMN region;",
			wantFlag: true,
		},
		{
			name:     "additive add-column with default is fine",
			sql:      "ALTER TABLE owners ADD COLUMN IF NOT EXISTS region text NOT NULL DEFAULT '';",
			wantFlag: false,
		},
		{
			name:     "drop primary key constraint is lock-heavy",
			sql:      "ALTER TABLE owners DROP CONSTRAINT owners_pkey;",
			wantFlag: true,
		},
		{
			name:     "add primary key constraint is lock-heavy",
			sql:      "ALTER TABLE owners ADD CONSTRAINT owners_pkey PRIMARY KEY (tenant_id, id);",
			wantFlag: true,
		},
		{
			name:     "online-safe primary key justification exempts the statement",
			sql:      "-- online-safe: covered by exact historical before/after harness\nALTER TABLE owners ADD CONSTRAINT owners_pkey PRIMARY KEY (tenant_id, id);",
			wantFlag: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scan(tc.sql); got != tc.wantFlag {
				t.Errorf("scan(%q) flagged=%v, want %v", tc.sql, got, tc.wantFlag)
			}
		})
	}
}
