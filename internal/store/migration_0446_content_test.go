// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0446KeepsSchedulesAndStartsWithNoLeaseTTL: 0446 records the
// lease TTL a dynamic-lease rotation schedule issues (A201-L1). Schedules
// projected before it keep every value and read a TTL of zero, which no
// connector or static schedule uses.
func TestMigration0446KeepsSchedulesAndStartsWithNoLeaseTTL(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 446)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "44600000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO secret_rotation_schedules
		(id, tenant_id, name, provider, secret_key, old_ref, interval_seconds, enabled, next_run_at, created_at, updated_at,
		 consumers, retire_after_seconds, single_phase_acknowledged)
		VALUES ('44600000-0000-4000-8000-0000000000d1', $1, 'orders-hourly', 'pg-main', 'db/orders', 'orders_app_a',
		 3600, true, '2026-11-01T01:00:00Z', '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z', '{orders-app}', 600, true)`, tenant); err != nil {
		t.Fatalf("seed a pre-0446 schedule: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const schedules = `SELECT id::text, name, provider, secret_key, old_ref, interval_seconds, enabled, next_run_at,
		array_to_string(consumers, ','), retire_after_seconds, single_phase_acknowledged FROM secret_rotation_schedules ORDER BY id`
	scheduleCount, scheduleSum := checksumQuery(t, ctx, pool, schedules)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if count, sum := checksumQuery(t, ctx, pool, schedules); scheduleCount != 1 || count != scheduleCount || sum != scheduleSum {
		t.Fatalf("0446 changed schedule content: %d/%s before, %d/%s after", scheduleCount, scheduleSum, count, sum)
	}
	var ttl int
	if err := pool.QueryRow(ctx, `SELECT ttl_seconds FROM secret_rotation_schedules`).Scan(&ttl); err != nil {
		t.Fatal(err)
	}
	if ttl != 0 {
		t.Fatalf("a pre-0446 schedule reads lease TTL %d, want 0", ttl)
	}
}
