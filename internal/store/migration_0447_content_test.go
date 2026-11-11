// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0447AdmitsApprovedScopedSyncs: 0447 widens the scoped sync mode
// check for approval-gated convergence (A237-L1). Definitions made before it
// keep every value and their mode, approved becomes a mode a definition can
// hold, and an unknown mode is still refused.
func TestMigration0447AdmitsApprovedScopedSyncs(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 447)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "44700000-0000-4000-8000-000000000001"
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
	for id, mode := range map[string]string{
		"44700000-0000-4000-8000-0000000000d1": "manual",
		"44700000-0000-4000-8000-0000000000d2": "auto",
	} {
		if err := withTenant(t, `INSERT INTO secret_scoped_syncs
			(tenant_id, id, name, source_prefix, target, destination_prefix, key_transform, delete_scope, adopt_existing,
			 defined_by, created_at, updated_at, event_sequence, mode)
			VALUES ($1, $2, 'payments-'||$3, 'payments/prod/', 'vault', 'payments', 'path', 'managed', false,
			 'operator', '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z', 7, $3)`, tenant, id, mode); err != nil {
			t.Fatalf("seed a pre-0447 %s scoped sync: %v", mode, err)
		}
	}
	if err := withTenant(t, `UPDATE secret_scoped_syncs SET mode = 'approved'`); err == nil {
		t.Fatal("before 0447 a scoped sync held the approved mode")
	}
	const stable = `SELECT tenant_id::text, id::text, name, source_prefix, target, destination_prefix, key_transform,
		delete_scope, adopt_existing, defined_by, created_at, updated_at, last_plan_digest, last_applied_at, event_sequence,
		mode, source_digest, last_reconcile_at, last_reconcile_status, last_reconcile_reason
		FROM secret_scoped_syncs ORDER BY id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if beforeCount != 2 || afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0447 changed scoped sync content: %d/%s before, %d/%s after", beforeCount, beforeChecksum, afterCount, afterChecksum)
	}
	if err := withTenant(t, `UPDATE secret_scoped_syncs SET mode = 'approved' WHERE id = '44700000-0000-4000-8000-0000000000d1'`); err != nil {
		t.Fatalf("after 0447 a scoped sync cannot hold the approved mode: %v", err)
	}
	if err := withTenant(t, `UPDATE secret_scoped_syncs SET mode = 'sometimes' WHERE id = '44700000-0000-4000-8000-0000000000d2'`); err == nil {
		t.Fatal("after 0447 a scoped sync took an unknown mode")
	}
}
