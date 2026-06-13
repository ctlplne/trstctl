package backup_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"trustctl.io/trustctl/internal/backup"
	"trustctl.io/trustctl/internal/store"
)

// migrationTables parses every CREATE TABLE in the migration SQL — the ground
// truth of which persistent stores exist.
func migrationTables(t *testing.T) []string {
	t.Helper()
	dir := filepath.FromSlash("../store/migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	re := regexp.MustCompile(`(?i)CREATE TABLE (?:IF NOT EXISTS )?([a-z_][a-z0-9_]*)`)
	seen := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			name := m[1]
			if name == "schema_migrations" { // the migration bookkeeping table, not app state
				continue
			}
			seen[name] = true
		}
	}
	var out []string
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// TestBackupManifestCoversEveryPersistentStore enforces the SF.4 convention: every
// table the migrations create is classified in the backup-set manifest, so a new
// persistent store cannot silently fall out of the disaster-recovery plan.
func TestBackupManifestCoversEveryPersistentStore(t *testing.T) {
	tables := migrationTables(t)
	if len(tables) < 10 {
		t.Fatalf("found only %d migration tables; parser likely broke", len(tables))
	}
	for _, tbl := range tables {
		if _, ok := backup.Classify(tbl); !ok {
			t.Errorf("persistent table %q is not in the backup-set manifest — classify it "+
				"(internal/backup/manifest.go): a log projection (RecoveredByLogRebuild), "+
				"independent PG state (RecoveredFromPostgresBackup), or Ephemeral", tbl)
		}
	}
}

// TestBackupManifestHasNoPhantomTables: every table named in the manifest must
// actually exist, so the manifest can't rot as tables are renamed/removed.
func TestBackupManifestHasNoPhantomTables(t *testing.T) {
	real := map[string]bool{}
	for _, tbl := range migrationTables(t) {
		real[tbl] = true
	}
	all := append(append(append([]string(nil),
		backup.RecoveredByLogRebuild...),
		backup.RecoveredFromPostgresBackup...),
		backup.Ephemeral...)
	for _, tbl := range all {
		if !real[tbl] {
			t.Errorf("manifest names table %q that no migration creates", tbl)
		}
	}
}

// TestManifestClassesAreDisjoint: a table belongs to exactly one recovery class.
func TestManifestClassesAreDisjoint(t *testing.T) {
	count := map[string]int{}
	for _, set := range [][]string{backup.RecoveredByLogRebuild, backup.RecoveredFromPostgresBackup, backup.Ephemeral} {
		for _, tbl := range set {
			count[tbl]++
		}
	}
	for tbl, n := range count {
		if n != 1 {
			t.Errorf("table %q appears in %d recovery classes; it must be in exactly one", tbl, n)
		}
	}
}

// TestLogRebuildSetMatchesProjections is the AN-2 guard: the manifest's
// "recovered by replaying the log" set must be exactly the read model that
// Rebuild truncates and re-derives. If a new event-sourced table is added to the
// projections but not wired into the rebuild (or vice versa), this fails — a
// restored control plane would otherwise carry stale or duplicated projection
// data.
func TestLogRebuildSetMatchesProjections(t *testing.T) {
	got := append([]string(nil), backup.RecoveredByLogRebuild...)
	want := append([]string(nil), store.ReadModelTables...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("RecoveredByLogRebuild = %v, want store.ReadModelTables = %v", got, want)
	}
}
