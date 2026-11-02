// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0372KeepsRotationsAndStartsWithNoRetirementGate: 0372 adds the
// retirement gate (A240) to rotation commands and schedules. A command and a
// schedule projected before it keep every value and read no consumers, a zero
// deadline, no approver and no retire_not_before, so they retire at
// verification as before; the new checks refuse a negative deadline.
func TestMigration0372KeepsRotationsAndStartsWithNoRetirementGate(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 372)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "37200000-0000-4000-8000-000000000001"
	withTenant := func(t *testing.T, statement string, args ...any) error {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, statement, args...); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err := withTenant(t, `INSERT INTO secret_static_rotation_commands
		(tenant_id, id, tenant_epoch, provider, provider_type, secret_key, old_ref, new_ref, phase,
		 expected_version, result_version, sealed_new, verify_mode, idempotency_key_digest, request_binding,
		 created_at, updated_at)
		VALUES ($1, '37200000-0000-4000-8000-0000000000c1', 'epoch-1', 'pg-main', 'postgresql', 'db/orders',
		 'orders_app_a', 'orders_app_b', 'verified', 2, 3, '\x0102'::bytea, 'connected', $2, $3,
		 '2026-11-01T00:00:00Z', '2026-11-01T00:05:00Z')`,
		tenant, "a"+repeatHex64(2), "b"+repeatHex64(2)); err != nil {
		t.Fatalf("seed a pre-0372 static command: %v", err)
	}
	if err := withTenant(t, `INSERT INTO secret_rotation_schedules
		(id, tenant_id, name, provider, secret_key, old_ref, interval_seconds, enabled, next_run_at, created_at, updated_at)
		VALUES ('37200000-0000-4000-8000-0000000000d1', $1, 'orders-hourly', 'pg-main', 'db/orders', 'orders_app_a',
		 3600, true, '2026-11-01T01:00:00Z', '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z')`, tenant); err != nil {
		t.Fatalf("seed a pre-0372 schedule: %v", err)
	}
	const commands = `SELECT tenant_id::text, id::text, tenant_epoch, provider, provider_type, secret_key, old_ref,
		new_ref, phase, expected_version, result_version, encode(sealed_new, 'hex'), verify_mode,
		idempotency_key_digest, request_binding, created_at, updated_at
		FROM secret_static_rotation_commands ORDER BY id`
	const schedules = `SELECT id::text, tenant_id::text, name, provider, secret_key, old_ref, interval_seconds,
		enabled, next_run_at, created_at, updated_at FROM secret_rotation_schedules ORDER BY id`
	commandCount, commandSum := checksumQuery(t, ctx, pool, commands)
	scheduleCount, scheduleSum := checksumQuery(t, ctx, pool, schedules)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if count, sum := checksumQuery(t, ctx, pool, commands); commandCount != 1 || count != commandCount || sum != commandSum {
		t.Fatalf("0372 changed rotation command content: %d/%s before, %d/%s after", commandCount, commandSum, count, sum)
	}
	if count, sum := checksumQuery(t, ctx, pool, schedules); scheduleCount != 1 || count != scheduleCount || sum != scheduleSum {
		t.Fatalf("0372 changed schedule content: %d/%s before, %d/%s after", scheduleCount, scheduleSum, count, sum)
	}
	var consumers, approvedBy string
	var after int
	var notBeforeNull bool
	if err := pool.QueryRow(ctx, `SELECT array_to_string(consumers, ','), retire_after_seconds, retire_approved_by,
		retire_not_before IS NULL FROM secret_static_rotation_commands`).Scan(&consumers, &after, &approvedBy, &notBeforeNull); err != nil {
		t.Fatal(err)
	}
	if consumers != "" || after != 0 || approvedBy != "" || !notBeforeNull {
		t.Fatalf("the command reads consumers %q, deadline %d, approver %q, retire_not_before null %v", consumers, after, approvedBy, notBeforeNull)
	}
	if err := pool.QueryRow(ctx, `SELECT array_to_string(consumers, ','), retire_after_seconds FROM secret_rotation_schedules`).Scan(&consumers, &after); err != nil {
		t.Fatal(err)
	}
	if consumers != "" || after != 0 {
		t.Fatalf("the schedule reads consumers %q, deadline %d", consumers, after)
	}
	if err := withTenant(t, `UPDATE secret_static_rotation_commands SET retire_after_seconds = -1`); err == nil {
		t.Fatal("a negative command deadline was stored")
	}
	if err := withTenant(t, `UPDATE secret_rotation_schedules SET retire_after_seconds = -1`); err == nil {
		t.Fatal("a negative schedule deadline was stored")
	}
}
