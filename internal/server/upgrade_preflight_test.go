// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

func findingCodes(fs []UpgradeFinding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.Code)
	}
	return out
}

func TestUpgradePreflightVerdicts(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	fresh := UpgradeBackup{Configured: true, Verified: true, TakenAt: now.Add(-time.Hour).Format(time.RFC3339), Fresh: true}
	additive := store.UpgradeMigration{Version: 376, Name: "0376_add.sql", Transactional: true}
	online := store.UpgradeMigration{Version: 377, Name: "0377_index.sql"}
	dropping := store.UpgradeMigration{Version: 378, Name: "0378_drop.sql", Destructive: true, Transactional: true}
	at := func(pending ...store.UpgradeMigration) store.UpgradePlan {
		return store.UpgradePlan{SchemaVersion: 375, BinaryVersion: 378, Pending: pending}
	}
	for _, tc := range []struct {
		name     string
		plan     store.UpgradePlan
		backup   UpgradeBackup
		ready    bool
		method   string
		blockers []string
		warnings []string
	}{
		{"nothing to apply", at(), UpgradeBackup{}, true, "none", nil, nil},
		{"a new database", store.UpgradePlan{BinaryVersion: 378, Pending: []store.UpgradeMigration{additive, online, dropping}}, UpgradeBackup{}, true, "rerun", nil, nil},
		{"additive with a backup", at(additive), fresh, true, "redeploy_previous_binary", nil, nil},
		{"additive without a backup", at(additive), UpgradeBackup{}, true, "redeploy_previous_binary", nil, []string{"no_fresh_backup"}},
		{"outside a transaction", at(online), fresh, true, "redeploy_previous_binary", nil, []string{"outside_transaction"}},
		{"destructive with a backup", at(additive, dropping), fresh, true, "restore_backup", nil, nil},
		{"destructive without a backup", at(dropping), UpgradeBackup{Configured: true, Verified: true, TakenAt: now.Add(-48 * time.Hour).Format(time.RFC3339)}, false, "restore_backup", []string{"backup_required"}, nil},
		{"edited migration", store.UpgradePlan{SchemaVersion: 375, BinaryVersion: 375, ChecksumMismatches: []string{"0370_x.sql"}}, fresh, false, "none", []string{"checksum_mismatch"}, nil},
		{"another run migrating", store.UpgradePlan{SchemaVersion: 375, BinaryVersion: 376, Pending: []store.UpgradeMigration{additive}, LockHeld: true}, fresh, false, "redeploy_previous_binary", []string{"migration_running"}, nil},
		{"an older binary", store.UpgradePlan{SchemaVersion: 376, BinaryVersion: 375, NewerThanBinary: []int64{376}}, fresh, true, "none", nil, []string{"schema_newer_than_binary"}},
		{"an invalid index", store.UpgradePlan{SchemaVersion: 375, BinaryVersion: 375, InvalidIndexes: []string{"x_idx"}}, fresh, true, "none", nil, []string{"invalid_index"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateUpgradePreflight(tc.plan, tc.backup, now)
			if got.Ready != tc.ready || got.Rollback.Method != tc.method {
				t.Errorf("ready %v, rollback %q; want %v, %q", got.Ready, got.Rollback.Method, tc.ready, tc.method)
			}
			if b := findingCodes(got.Blockers); !slices.Equal(b, append([]string{}, tc.blockers...)) {
				t.Errorf("blockers %v; want %v", b, tc.blockers)
			}
			if w := findingCodes(got.Warnings); !slices.Equal(w, append([]string{}, tc.warnings...)) {
				t.Errorf("warnings %v; want %v", w, tc.warnings)
			}
		})
	}
}

// writeVerifiedBackup writes a one-artifact full backup taken at takenAt.
func writeVerifiedBackup(t *testing.T, takenAt time.Time) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "events.bin"), []byte("event log"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum, n, err := backup.HashFile(filepath.Join(dir, "events.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.WriteFullManifest(filepath.Join(dir, backup.FullManifestName), backup.FullManifest{
		Format: "trstctl-full-backup", Version: 1, CreatedAt: takenAt,
		Artifacts: []backup.Artifact{{Name: "events", Role: "event-log", Path: "events.bin", SHA256: sum, Bytes: n, Exists: true, Captured: true, Required: true}},
	}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestUpgradePreflightReadsTheConfiguredBackup(t *testing.T) {
	now := time.Now()
	if got := upgradeBackupState("", now); got.Configured || got.Fresh || got.Detail == "" {
		t.Errorf("no directory: %+v", got)
	}
	if got := upgradeBackupState(t.TempDir(), now); !got.Configured || got.Fresh || got.Detail == "" {
		t.Errorf("an empty directory: %+v", got)
	}
	if got := upgradeBackupState(writeVerifiedBackup(t, now.Add(-time.Hour)), now); !got.Fresh || !got.Verified {
		t.Errorf("a verified backup from an hour ago: %+v", got)
	}
	if got := upgradeBackupState(writeVerifiedBackup(t, now.Add(-backup.FreshFor-time.Hour)), now); got.Fresh || !got.Verified {
		t.Errorf("a verified backup older than %s: %+v", backup.FreshFor, got)
	}
	tampered := writeVerifiedBackup(t, now.Add(-time.Hour))
	if err := os.WriteFile(filepath.Join(tampered, "events.bin"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := upgradeBackupState(tampered, now); got.Fresh || got.Verified {
		t.Errorf("a backup whose bytes changed: %+v", got)
	}
}

// The preflight the CLI runs, against a real database: it reads the position
// and the backup and changes nothing.
func TestUpgradePreflightAgainstADatabaseChangesNothing(t *testing.T) {
	ctx := t.Context()
	dsn := freshServerTestDatabase(t)
	cfg := config.Default()
	cfg.Postgres.Mode = config.PostgresExternal
	cfg.Postgres.DSN = dsn
	ext := func(files map[string]string) []fs.FS {
		m := fstest.MapFS{}
		for name, body := range files {
			m["migrations/"+name] = &fstest.MapFile{Data: []byte(body)}
		}
		return []fs.FS{m}
	}

	// A new database.
	verdict, err := RunUpgradePreflight(ctx, cfg, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.Ready || verdict.Rollback.Method != "rerun" || verdict.SchemaVersion != 0 || len(verdict.Pending) == 0 {
		t.Fatalf("a new database: ready %v, rollback %q, schema %d, pending %d", verdict.Ready, verdict.Rollback.Method, verdict.SchemaVersion, len(verdict.Pending))
	}
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var ledger bool
	if err := st.SystemPool().QueryRow(ctx, "SELECT to_regclass('public.schema_migrations') IS NOT NULL").Scan(&ledger); err != nil || ledger {
		t.Fatalf("the preflight wrote to a new database: ledger=%v err=%v", ledger, err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	// An additive upgrade with no backup directory: ready, with a warning.
	verdict, err = RunUpgradePreflight(ctx, cfg, ext(map[string]string{"990001_add.sql": "CREATE TABLE preflight_probe (k int);"}), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.Ready || verdict.Rollback.Method != "redeploy_previous_binary" || !slices.Equal(findingCodes(verdict.Warnings), []string{"no_fresh_backup"}) {
		t.Fatalf("an additive upgrade: %+v", verdict)
	}

	// A destructive one: blocked until a fresh verified backup is visible.
	destructive := ext(map[string]string{"990001_add.sql": "CREATE TABLE preflight_probe (k int);", "990002_drop.sql": "DROP TABLE preflight_probe;"})
	verdict, err = RunUpgradePreflight(ctx, cfg, destructive, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var text bytes.Buffer
	verdict.WriteText(&text)
	if verdict.Ready || !strings.Contains(text.String(), "upgrade preflight: not ready") || !strings.Contains(text.String(), "blocker backup_required") || !strings.Contains(text.String(), "990002_drop.sql (destructive)") {
		t.Fatalf("a destructive upgrade without a backup:\n%s", text.String())
	}
	if strings.Contains(text.String(), dsn) || strings.Contains(text.String(), "DROP TABLE") {
		t.Fatalf("the report carries the connection string or a migration's SQL:\n%s", text.String())
	}
	cfg.Backup.Directory = writeVerifiedBackup(t, time.Now().Add(-time.Hour))
	if verdict, err = RunUpgradePreflight(ctx, cfg, destructive, time.Now()); err != nil || !verdict.Ready || verdict.Rollback.Method != "restore_backup" {
		t.Fatalf("a destructive upgrade with a fresh backup: %+v (%v)", verdict, err)
	}
	if err := st.SystemPool().QueryRow(ctx, "SELECT to_regclass('preflight_probe') IS NOT NULL").Scan(&ledger); err != nil || ledger {
		t.Fatalf("the preflight applied a migration: %v %v", ledger, err)
	}
}

// A migration that fails at startup says what state the database is in and the
// two ways on.
func TestFailedStartupMigrationSaysHowToRecover(t *testing.T) {
	ctx := t.Context()
	dsn := freshServerTestDatabase(t)
	cfg := config.Default()
	cfg.Postgres.Mode = config.PostgresExternal
	cfg.Postgres.DSN = dsn
	cfg.Migrate.Auto = true
	ext := fstest.MapFS{"migrations/990001_fails.sql": {Data: []byte("CREATE TABLE fails_probe (k int); SELECT 1/0;")}}
	st, stop, err := openMigratedStore(ctx, cfg, slog.New(slog.DiscardHandler), []fs.FS{ext})
	if err == nil {
		st.Close()
		if stop != nil {
			_ = stop()
		}
		t.Fatal("a failing migration started the server")
	}
	if !strings.Contains(err.Error(), "990001_fails.sql") || !strings.Contains(err.Error(), failedUpgradeHint) {
		t.Fatalf("startup failure %q; want the migration named and the recovery hint", err)
	}
}
