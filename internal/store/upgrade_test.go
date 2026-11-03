// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/store"
)

// release is one binary's extension migrations, on top of the core set.
func release(files map[string]string) fs.FS {
	out := fstest.MapFS{}
	for name, body := range files {
		out["migrations/"+name] = &fstest.MapFile{Data: []byte(body)}
	}
	return out
}

func openRelease(t *testing.T, dsn string, ext fs.FS) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if ext != nil {
		s.WithExtraMigrations(ext)
	}
	return s
}

func lastCoreMigrationVersion(t *testing.T) int64 {
	t.Helper()
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	var last string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			last = e.Name()
		}
	}
	return int64(migrationNumber(last))
}

func ledgerHas(t *testing.T, pool *pgxpool.Pool, version int64) bool {
	t.Helper()
	var ok bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}

func relationExists(t *testing.T, pool *pgxpool.Pool, name string) bool {
	t.Helper()
	var ok bool
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}

// The boot gate under TRSTCTL_MIGRATE_AUTO=false and `trstctl --migrate-status`
// read PendingMigrations; an extension's migration the database has not applied
// is as pending as a core one.
func TestPendingMigrationsCountsExtensionMigrations(t *testing.T) {
	ctx := t.Context()
	dsn := createFreshMigrationDatabase(t)
	if err := openRelease(t, dsn, nil).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	next := openRelease(t, dsn, release(map[string]string{"990001_upgrade_probe.sql": "CREATE TABLE upgrade_probe (k int);"}))
	pending, err := next.PendingMigrations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pending, []string{"990001_upgrade_probe.sql"}) {
		t.Fatalf("pending = %v; want the extension's migration", pending)
	}
}

// The upgrade plan reads where the database stands against a binary's
// migrations and changes nothing.
func TestUpgradePlanReadsTheDatabasePositionWithoutWriting(t *testing.T) {
	ctx := t.Context()
	dsn := createFreshMigrationDatabase(t)
	ext := release(map[string]string{
		"990001_probe_table.sql":    "CREATE TABLE upgrade_probe (k int, note text);",
		"990002_probe_drop.sql":     "ALTER TABLE upgrade_probe DROP COLUMN note;",
		"990003_probe_index_nt.sql": "-- migrate: no-transaction\nCREATE INDEX CONCURRENTLY IF NOT EXISTS upgrade_probe_k_idx ON upgrade_probe (k);",
	})
	fresh := openRelease(t, dsn, ext)
	plan, err := fresh.UpgradePlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	core := lastCoreMigrationVersion(t)
	if plan.SchemaVersion != 0 || plan.BinaryVersion != core || len(plan.Pending) != int(core)+3 {
		t.Fatalf("fresh database: schema %d binary %d pending %d; want 0, %d, %d", plan.SchemaVersion, plan.BinaryVersion, len(plan.Pending), core, core+3)
	}
	if relationExists(t, fresh.SystemPool(), "public.schema_migrations") {
		t.Fatal("reading the plan created the migration ledger")
	}

	// The previous release: core and the first extension migration.
	previous := openRelease(t, dsn, release(map[string]string{"990001_probe_table.sql": "CREATE TABLE upgrade_probe (k int, note text);"}))
	if err := previous.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	plan, err = fresh.UpgradePlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SchemaVersion != core {
		t.Fatalf("schema version %d; want %d", plan.SchemaVersion, core)
	}
	want := []store.UpgradeMigration{
		{Version: 990002, Name: "990002_probe_drop.sql", Destructive: true, Transactional: true},
		{Version: 990003, Name: "990003_probe_index_nt.sql", Destructive: false, Transactional: false},
	}
	if !slices.Equal(plan.Pending, want) {
		t.Fatalf("pending %+v; want %+v", plan.Pending, want)
	}
	if len(plan.ChecksumMismatches)+len(plan.NewerThanBinary)+len(plan.InvalidIndexes) != 0 || plan.LockHeld {
		t.Fatalf("a clean position reported findings: %+v", plan)
	}

	// An applied file that changed since it ran.
	edited := openRelease(t, dsn, release(map[string]string{"990001_probe_table.sql": "CREATE TABLE upgrade_probe (k bigint, note text);"}))
	if plan, err = edited.UpgradePlan(ctx); err != nil || !slices.Equal(plan.ChecksumMismatches, []string{"990001_probe_table.sql"}) {
		t.Fatalf("checksum mismatches %v (%v); want the edited file", plan.ChecksumMismatches, err)
	}

	// A binary older than the database: it has no file for 990001.
	older := openRelease(t, dsn, nil)
	if plan, err = older.UpgradePlan(ctx); err != nil || !slices.Equal(plan.NewerThanBinary, []int64{990001}) {
		t.Fatalf("newer than binary %v (%v); want [990001]", plan.NewerThanBinary, err)
	}

	// Another run holding the migration lock; the probe never keeps it.
	holder, err := previous.SystemPool().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, "SELECT pg_advisory_lock($1)", store.MigrateAdvisoryLockKey); err != nil {
		t.Fatal(err)
	}
	if plan, err = fresh.UpgradePlan(ctx); err != nil || !plan.LockHeld {
		t.Fatalf("lock held = %v (%v); want true", plan.LockHeld, err)
	}
	if _, err := holder.Exec(ctx, "SELECT pg_advisory_unlock($1)", store.MigrateAdvisoryLockKey); err != nil {
		t.Fatal(err)
	}
	holder.Release()
	if plan, err = fresh.UpgradePlan(ctx); err != nil || plan.LockHeld {
		t.Fatalf("lock held = %v (%v) after release; want false", plan.LockHeld, err)
	}
	var free bool
	if err := previous.SystemPool().QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", store.MigrateAdvisoryLockKey).Scan(&free); err != nil || !free {
		t.Fatalf("the plan's probe kept the migration lock: free=%v err=%v", free, err)
	}
	if _, err := previous.SystemPool().Exec(ctx, "SELECT pg_advisory_unlock_all()"); err != nil {
		t.Fatal(err)
	}

	// An index a failed concurrent build left invalid.
	if _, err := previous.SystemPool().Exec(ctx, "INSERT INTO upgrade_probe (k) VALUES (1), (1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := previous.SystemPool().Exec(ctx, "CREATE UNIQUE INDEX CONCURRENTLY upgrade_probe_k_uq ON upgrade_probe (k)"); err == nil {
		t.Fatal("a unique build over duplicates succeeded")
	}
	if plan, err = fresh.UpgradePlan(ctx); err != nil || !slices.Equal(plan.InvalidIndexes, []string{"upgrade_probe_k_uq"}) {
		t.Fatalf("invalid indexes %v (%v); want [upgrade_probe_k_uq]", plan.InvalidIndexes, err)
	}
}

// A246 "Done when": a failed upgrade keeps recoverable, compatible state. A
// release whose migration fails leaves every migration before it applied and
// the failed one rolled back; the previous release still runs against that
// schema and serves; the fixed release then applies. A concurrent index build
// that fails takes its invalid index with it, so the previous release's writes
// are as they were, and the next run builds it.
func TestFailedUpgradeKeepsRecoverableCompatibleState(t *testing.T) {
	ctx := t.Context()
	dsn := createFreshMigrationDatabase(t)
	const tenant = "5a1f0c6e-7d2b-4c1e-9a3f-2b6d8e4f1a01"
	v1 := map[string]string{"990001_notes.sql": "CREATE TABLE upgrade_notes (id bigserial PRIMARY KEY, note text NOT NULL);"}
	with := func(base map[string]string, more map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range more {
			out[k] = v
		}
		return out
	}

	// The release in service: it migrates and holds data.
	previous := openRelease(t, dsn, release(v1))
	if err := previous.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := previous.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "Before the upgrade"}); err != nil {
		t.Fatal(err)
	}
	if _, err := previous.SystemPool().Exec(ctx, "INSERT INTO upgrade_notes (note) VALUES ('kept')"); err != nil {
		t.Fatal(err)
	}

	// The upgrade: one additive migration, then one that fails partway.
	v2 := with(v1, map[string]string{
		"990002_labels.sql": "ALTER TABLE upgrade_notes ADD COLUMN label text;",
		"990003_archive.sql": "CREATE TABLE upgrade_notes_archive (id bigint); " +
			"INSERT INTO upgrade_notes_archive SELECT id FROM upgrade_notes; SELECT 1/0;",
	})
	err := openRelease(t, dsn, release(v2)).Migrate(ctx)
	if err == nil || !strings.Contains(err.Error(), "990003_archive.sql") {
		t.Fatalf("the failing upgrade = %v; want it to stop at 990003_archive.sql", err)
	}
	pool := previous.SystemPool()
	if !ledgerHas(t, pool, 990002) || ledgerHas(t, pool, 990003) {
		t.Fatal("after the failure the ledger must hold 990002 and not 990003")
	}
	if relationExists(t, pool, "upgrade_notes_archive") {
		t.Fatal("the failed migration's table survived its rollback")
	}
	var free bool
	if err := pool.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", store.MigrateAdvisoryLockKey).Scan(&free); err != nil || !free {
		t.Fatalf("the failed run kept the migration lock: free=%v err=%v", free, err)
	}
	if _, err := pool.Exec(ctx, "SELECT pg_advisory_unlock_all()"); err != nil {
		t.Fatal(err)
	}

	// Rolled back to the previous release: it starts against the newer schema,
	// sees it as newer, and reads and writes as before.
	rolledBack := openRelease(t, dsn, release(v1))
	if err := rolledBack.Migrate(ctx); err != nil {
		t.Fatalf("the previous release does not start after the failed upgrade: %v", err)
	}
	plan, err := rolledBack.UpgradePlan(ctx)
	if err != nil || !slices.Equal(plan.NewerThanBinary, []int64{990002}) || len(plan.Pending) != 0 {
		t.Fatalf("the previous release's plan: %+v (%v); want 990002 newer and nothing pending", plan, err)
	}
	if err := rolledBack.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "After the rollback"}); err != nil {
		t.Fatalf("the previous release cannot write after the failed upgrade: %v", err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO upgrade_notes (note) VALUES ('written by the previous release')"); err != nil {
		t.Fatal(err)
	}
	got, err := rolledBack.GetTenant(ctx, tenant)
	if err != nil || got.Name != "After the rollback" {
		t.Fatalf("tenant after the rollback: %+v (%v)", got, err)
	}

	// The fixed release applies what failed.
	v2fixed := with(v1, map[string]string{
		"990002_labels.sql":  v2["990002_labels.sql"],
		"990003_archive.sql": "CREATE TABLE upgrade_notes_archive (id bigint); INSERT INTO upgrade_notes_archive SELECT id FROM upgrade_notes;",
	})
	if err := openRelease(t, dsn, release(v2fixed)).Migrate(ctx); err != nil {
		t.Fatalf("the fixed release: %v", err)
	}
	var archived int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM upgrade_notes_archive").Scan(&archived); err != nil || archived != 2 {
		t.Fatalf("archived %d (%v); want both notes", archived, err)
	}

	// A concurrent unique build that fails over live duplicates.
	if _, err := pool.Exec(ctx, "INSERT INTO upgrade_notes (note) VALUES ('twice'), ('twice')"); err != nil {
		t.Fatal(err)
	}
	v3 := with(v2fixed, map[string]string{
		"990004_note_unique.sql": "-- migrate: no-transaction\nCREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS upgrade_notes_note_uq ON upgrade_notes (note);",
	})
	if err := openRelease(t, dsn, release(v3)).Migrate(ctx); err == nil {
		t.Fatal("a unique build over duplicates succeeded")
	}
	if relationExists(t, pool, "upgrade_notes_note_uq") || ledgerHas(t, pool, 990004) {
		t.Fatal("the failed concurrent build left its index (or a ledger row) behind")
	}
	if _, err := pool.Exec(ctx, "INSERT INTO upgrade_notes (note) VALUES ('twice')"); err != nil {
		t.Fatalf("the previous release's write after the failed build: %v", err)
	}

	// An invalid index left by a run that died partway is rebuilt by the next.
	if _, err := pool.Exec(ctx, "CREATE UNIQUE INDEX CONCURRENTLY upgrade_notes_note_uq ON upgrade_notes (note)"); err == nil {
		t.Fatal("a unique build over duplicates succeeded")
	}
	if !relationExists(t, pool, "upgrade_notes_note_uq") {
		t.Fatal("the interrupted build left no index to recover from")
	}
	if _, err := pool.Exec(ctx, "DELETE FROM upgrade_notes WHERE note = 'twice'"); err != nil {
		t.Fatal(err)
	}
	if err := openRelease(t, dsn, release(v3)).Migrate(ctx); err != nil {
		t.Fatalf("the run after the data was fixed: %v", err)
	}
	var healthy bool
	if err := pool.QueryRow(ctx, `SELECT i.indisvalid AND i.indisready FROM pg_index i WHERE i.indexrelid = to_regclass('upgrade_notes_note_uq')`).Scan(&healthy); err != nil || !healthy || !ledgerHas(t, pool, 990004) {
		t.Fatalf("the rebuilt index: healthy=%v err=%v ledgered=%v", healthy, err, ledgerHas(t, pool, 990004))
	}
}
