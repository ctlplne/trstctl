// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0472KeepsScopedSyncsOnTheDefaultInterval: 0472 adds a scoped
// sync's own drift-check interval (A237-L7). A definition made before it keeps
// every value and reads the default interval (0); the new check refuses an
// interval under a minute or over a day and admits one inside the range.
func TestMigration0472KeepsScopedSyncsOnTheDefaultInterval(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 472)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "47200000-0000-4000-8000-000000000001"
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
	if err := withTenant(t, `INSERT INTO secret_scoped_syncs
		(tenant_id, id, name, source_prefix, target, destination_prefix, key_transform, delete_scope, adopt_existing,
		 defined_by, created_at, updated_at, event_sequence, mode)
		VALUES ($1, '47200000-0000-4000-8000-0000000000d1', 'payments-prod', 'payments/prod/', 'vault', 'payments',
		 'path', 'managed', false, 'operator', '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z', 7, 'auto')`, tenant); err != nil {
		t.Fatalf("seed a pre-0472 scoped sync: %v", err)
	}
	const stable = `SELECT tenant_id::text, id::text, name, source_prefix, target, destination_prefix, key_transform,
		delete_scope, adopt_existing, defined_by, created_at, updated_at, last_plan_digest, last_applied_at, event_sequence,
		mode, source_digest, last_reconcile_at, last_reconcile_status, last_reconcile_reason
		FROM secret_scoped_syncs ORDER BY id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if beforeCount != 1 || afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0472 changed scoped sync content: %d/%s before, %d/%s after", beforeCount, beforeChecksum, afterCount, afterChecksum)
	}
	var interval int
	if err := pool.QueryRow(ctx, `SELECT reconcile_interval_seconds FROM secret_scoped_syncs`).Scan(&interval); err != nil {
		t.Fatal(err)
	}
	if interval != 0 {
		t.Fatalf("a pre-0472 sync reads interval %d, want the default 0", interval)
	}
	for _, bad := range []int{30, 86401} {
		if err := withTenant(t, `UPDATE secret_scoped_syncs SET reconcile_interval_seconds = $1`, bad); err == nil {
			t.Fatalf("an interval of %d seconds was stored", bad)
		}
	}
	if err := withTenant(t, `UPDATE secret_scoped_syncs SET reconcile_interval_seconds = 3600`); err != nil {
		t.Fatalf("an hourly interval was refused: %v", err)
	}
}
