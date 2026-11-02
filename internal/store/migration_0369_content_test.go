// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0369KeepsScopedSyncsManual: 0369 adds continuous mode to scoped
// syncs (A237). A definition made before it keeps every value, reads as manual
// with no reconcile yet, and the new check refuses an unknown mode.
func TestMigration0369KeepsScopedSyncsManual(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 369)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "36900000-0000-4000-8000-000000000001"
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
		 defined_by, created_at, updated_at, event_sequence)
		VALUES ($1, '36900000-0000-4000-8000-0000000000d1', 'payments-prod', 'payments/prod/', 'vault', 'payments',
		 'path', 'managed', false, 'operator', '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z', 7)`, tenant); err != nil {
		t.Fatalf("seed a pre-0369 scoped sync: %v", err)
	}
	const stable = `SELECT tenant_id::text, id::text, name, source_prefix, target, destination_prefix, key_transform,
		delete_scope, adopt_existing, defined_by, created_at, updated_at, last_plan_digest, last_applied_at, event_sequence
		FROM secret_scoped_syncs ORDER BY id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if beforeCount != 1 || afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0369 changed scoped sync content: %d/%s before, %d/%s after", beforeCount, beforeChecksum, afterCount, afterChecksum)
	}
	var mode, status string
	var reconciledNull bool
	if err := pool.QueryRow(ctx, `SELECT mode, last_reconcile_status, last_reconcile_at IS NULL FROM secret_scoped_syncs`).
		Scan(&mode, &status, &reconciledNull); err != nil {
		t.Fatal(err)
	}
	if mode != "manual" || status != "" || !reconciledNull {
		t.Fatalf("a pre-0369 sync reads mode %q status %q reconciled-null %v; want manual, empty, null", mode, status, reconciledNull)
	}
	if err := withTenant(t, `UPDATE secret_scoped_syncs SET mode = 'sometimes'`); err == nil {
		t.Fatal("an unknown scoped sync mode was stored")
	}
}
