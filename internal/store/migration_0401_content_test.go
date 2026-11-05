// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0401KeepsTargetsLeased is 0401's exact N-1 -> N case (A261):
// a target registered before names no account secret, so its sessions keep
// their per-session leases, and every pre-existing value is unchanged.
func TestMigration0401KeepsTargetsLeased(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 401)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "40100000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO pam_targets (tenant_id, target_type, id, provider_id, allowed_roles, enabled, registered_by, registered_at)
		VALUES ($1, 'postgres', 'orders-db', 'orders-pg', ARRAY['readonly'], true, 'op', '2026-11-05T01:00:00Z')`, tenant); err != nil {
		t.Fatalf("seed a pre-0401 target: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const targets = `SELECT (to_jsonb(o) - 'account_secret')::text FROM pam_targets o ORDER BY id`
	before, beforeSum := checksumQuery(t, ctx, pool, targets)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	if after, afterSum := checksumQuery(t, ctx, pool, targets); before != 1 || after != before || afterSum != beforeSum {
		t.Fatalf("0401 changed target content: %d/%s before, %d/%s after", before, beforeSum, after, afterSum)
	}
	var vaulted int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_targets WHERE account_secret <> ''`).Scan(&vaulted); err != nil {
		t.Fatal(err)
	}
	if vaulted != 0 {
		t.Fatalf("%d pre-0401 targets became vaulted", vaulted)
	}
}
