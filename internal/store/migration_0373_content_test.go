// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0373KeepsRotationsUnacknowledged: 0373 records a single-phase
// rotation's acknowledgement (A240) on commands and schedules. Rows projected
// before it keep every value and read unacknowledged, which no two-phase
// provider needs.
func TestMigration0373KeepsRotationsUnacknowledged(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 373)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "37300000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO secret_static_rotation_commands
		(tenant_id, id, tenant_epoch, provider, provider_type, secret_key, old_ref, new_ref, phase,
		 expected_version, result_version, verify_mode, idempotency_key_digest, request_binding,
		 created_at, updated_at, consumers, retire_after_seconds, retire_approved_by)
		VALUES ($1, '37300000-0000-4000-8000-0000000000c1', 'epoch-1', 'pg-main', 'postgresql', 'db/orders',
		 'orders_app_a', 'orders_app_b', 'completed', 2, 3, 'connected', $2, $3,
		 '2026-11-01T00:00:00Z', '2026-11-01T00:05:00Z', '{orders-app}', 600, 'operator')`,
		tenant, "a"+repeatHex64(3), "b"+repeatHex64(3)); err != nil {
		t.Fatalf("seed a pre-0373 command: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO secret_rotation_schedules
		(id, tenant_id, name, provider, secret_key, old_ref, interval_seconds, enabled, next_run_at, created_at, updated_at,
		 consumers, retire_after_seconds)
		VALUES ('37300000-0000-4000-8000-0000000000d1', $1, 'orders-hourly', 'pg-main', 'db/orders', 'orders_app_a',
		 3600, true, '2026-11-01T01:00:00Z', '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z', '{orders-app}', 600)`, tenant); err != nil {
		t.Fatalf("seed a pre-0373 schedule: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const commands = `SELECT tenant_id::text, id::text, provider, secret_key, old_ref, new_ref, phase, result_version,
		array_to_string(consumers, ','), retire_after_seconds, retire_approved_by, created_at, updated_at
		FROM secret_static_rotation_commands ORDER BY id`
	const schedules = `SELECT id::text, name, provider, secret_key, old_ref, interval_seconds, enabled, next_run_at,
		array_to_string(consumers, ','), retire_after_seconds FROM secret_rotation_schedules ORDER BY id`
	commandCount, commandSum := checksumQuery(t, ctx, pool, commands)
	scheduleCount, scheduleSum := checksumQuery(t, ctx, pool, schedules)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if count, sum := checksumQuery(t, ctx, pool, commands); commandCount != 1 || count != commandCount || sum != commandSum {
		t.Fatalf("0373 changed rotation command content: %d/%s before, %d/%s after", commandCount, commandSum, count, sum)
	}
	if count, sum := checksumQuery(t, ctx, pool, schedules); scheduleCount != 1 || count != scheduleCount || sum != scheduleSum {
		t.Fatalf("0373 changed schedule content: %d/%s before, %d/%s after", scheduleCount, scheduleSum, count, sum)
	}
	var commandAck, scheduleAck bool
	if err := pool.QueryRow(ctx, `SELECT single_phase_acknowledged FROM secret_static_rotation_commands`).Scan(&commandAck); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT single_phase_acknowledged FROM secret_rotation_schedules`).Scan(&scheduleAck); err != nil {
		t.Fatal(err)
	}
	if commandAck || scheduleAck {
		t.Fatalf("pre-0373 rows read acknowledged: command %v schedule %v", commandAck, scheduleAck)
	}
}
