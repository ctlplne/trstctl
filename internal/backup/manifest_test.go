// SPDX-License-Identifier: BUSL-1.1

package backup_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/store"
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
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
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

// TestDeploymentTargetsUseOnePostgresRecoveryClass pins the migration-0072
// exception: legacy targets and their generated immutable revisions have no
// historical events, so neither table can be reconstructed by log replay.
func TestDeploymentTargetsUseOnePostgresRecoveryClass(t *testing.T) {
	for _, table := range []string{"deployment_target_revisions", "deployment_targets"} {
		class, ok := backup.Classify(table)
		if !ok {
			t.Fatalf("%s is missing from the recovery manifest", table)
		}
		if class != backup.ClassPostgresBackup {
			t.Errorf("%s recovery class = %q, want %q", table, class, backup.ClassPostgresBackup)
		}
		for _, rebuilt := range store.ReadModelTables {
			if rebuilt == table {
				t.Errorf("%s is also in store.ReadModelTables; one table cannot use two recovery paths", table)
			}
		}
	}
}

func TestPrivacyErasureOperationsSurviveLogReadModelRebuild(t *testing.T) {
	const table = "privacy_subject_erasure_operations"
	class, ok := backup.Classify(table)
	if !ok {
		t.Fatalf("%s is missing from the recovery manifest", table)
	}
	if class != backup.ClassPostgresBackup {
		t.Fatalf("%s recovery class = %q, want %q", table, class, backup.ClassPostgresBackup)
	}
	for _, rebuilt := range store.ReadModelTables {
		if rebuilt == table {
			t.Fatalf("%s is also in store.ReadModelTables; retained events cannot rebuild long-window idempotency evidence", table)
		}
	}
}

func TestPrivacyErasurePreparationsAreDurablePostgresRecoveryAuthority(t *testing.T) {
	const table = "privacy_subject_erasure_preparations"
	class, ok := backup.Classify(table)
	if !ok {
		t.Fatalf("%s is missing from the recovery manifest", table)
	}
	if class != backup.ClassPostgresBackup {
		t.Fatalf("%s recovery class = %q, want %q", table, class, backup.ClassPostgresBackup)
	}
	for _, rebuilt := range store.ReadModelTables {
		if rebuilt == table {
			t.Fatalf("%s is also in store.ReadModelTables; rebuild would erase the cross-store crash marker", table)
		}
	}
}

func TestApprovedTargetFencesSurviveLogReadModelRebuildAUD77(t *testing.T) {
	const table = "approved_target_event_fences"
	class, ok := backup.Classify(table)
	if !ok {
		t.Fatalf("%s is missing from the recovery manifest", table)
	}
	if class != backup.ClassPostgresBackup {
		t.Fatalf("%s recovery class = %q, want %q", table, class, backup.ClassPostgresBackup)
	}
	for _, rebuilt := range store.ReadModelTables {
		if rebuilt == table {
			t.Fatalf("%s is also in store.ReadModelTables; rebuild would erase an unprojected canonical command", table)
		}
	}
}

func TestSecretRotationScheduleCommandsSurviveLogReadModelRebuildAUD106(t *testing.T) {
	for _, table := range []string{
		"secret_rotation_schedule_scan_cursors",
		"secret_rotation_schedule_ticks",
		"secret_rotation_schedule_tick_rows",
		"secret_rotation_schedule_commands",
	} {
		class, ok := backup.Classify(table)
		if !ok {
			t.Fatalf("%s is missing from the recovery manifest", table)
		}
		if class != backup.ClassPostgresBackup {
			t.Fatalf("%s recovery class = %q, want %q", table, class, backup.ClassPostgresBackup)
		}
		for _, rebuilt := range store.ReadModelTables {
			if rebuilt == table {
				t.Fatalf("%s is also in store.ReadModelTables; rebuild would erase scheduler crash authority", table)
			}
		}
	}
}

func TestOperationApprovalRecoveryClassesAUD77(t *testing.T) {
	for _, table := range []string{"operation_approval_requests", "operation_approval_decisions"} {
		class, ok := backup.Classify(table)
		if !ok {
			t.Fatalf("%s is missing from the recovery manifest", table)
		}
		if class != backup.ClassLogRebuild {
			t.Errorf("%s recovery class = %q, want %q", table, class, backup.ClassLogRebuild)
		}
	}
	for _, table := range []string{"issuance_approval_requests", "issuance_approvals"} {
		class, ok := backup.Classify(table)
		if !ok {
			t.Fatalf("legacy table %s is missing from the recovery manifest", table)
		}
		if class != backup.ClassPostgresBackup {
			t.Errorf("legacy table %s recovery class = %q, want %q", table, class, backup.ClassPostgresBackup)
		}
	}
}
