// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0397KeepsBundlesWithoutDelegatedAccounts is 0397's exact N-1 ->
// N case (A257): a bundle saved before names no access targets, and every
// pre-existing value is unchanged.
func TestMigration0397KeepsBundlesWithoutDelegatedAccounts(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 397)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "39700000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO access_bundles (tenant_id, id, name, description, permissions, audiences,
		        max_run_ttl_seconds, revision, created_by, created_at, updated_at, event_sequence)
		VALUES ($1, '39700000-0000-4000-8000-0000000000a1', 'deploy', 'ci deploys', ARRAY['certs:read'], ARRAY['ci'],
		        900, 1, 'op', '2026-11-04T08:00:00Z', '2026-11-04T08:00:00Z', 7)`, tenant); err != nil {
		t.Fatalf("seed a pre-0397 bundle: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const bundles = `SELECT (to_jsonb(o) - 'access_targets')::text FROM access_bundles o ORDER BY id`
	before, beforeSum := checksumQuery(t, ctx, pool, bundles)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	if after, afterSum := checksumQuery(t, ctx, pool, bundles); before != 1 || after != before || afterSum != beforeSum {
		t.Fatalf("0397 changed bundle content: %d/%s before, %d/%s after", before, beforeSum, after, afterSum)
	}
	var delegated int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM access_bundles WHERE access_targets <> '[]'::jsonb`).Scan(&delegated); err != nil {
		t.Fatal(err)
	}
	if delegated != 0 {
		t.Fatalf("%d pre-0397 bundles gained delegated accounts", delegated)
	}
}
