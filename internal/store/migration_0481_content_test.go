// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// P15-L7: 0481 only adds the shared ACME nonce and finalize-claim tables,
// tenant isolated; rows already stored elsewhere keep all their content.
func TestMigration0481AddsIsolatedACMEReplicaStateOnly(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 481)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	const tenant = "48100000-0000-4000-8000-000000000001"
	if _, err := pool.Exec(ctx, `INSERT INTO machine_credential_replays (tenant_id, method, key_digest, expires_at, used_at)
		VALUES ($1, 'jwt', 'p15l7-key', '2026-11-15T00:00:00Z', '2026-11-14T00:00:00Z')`, tenant); err != nil {
		t.Fatalf("seed a pre-0481 row: %v", err)
	}
	const rows = `SELECT tenant_id::text, method, key_digest, expires_at, used_at FROM machine_credential_replays ORDER BY key_digest`
	count, sum := checksumQuery(t, ctx, pool, rows)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, after := checksumQuery(t, ctx, pool, rows); count != 1 || n != count || after != sum {
		t.Fatalf("0481 changed stored rows: %d/%s before, %d/%s after", count, sum, n, after)
	}
	for _, table := range []string{"acme_nonces", "acme_finalize_claims"} {
		var rls, forced bool
		var n int
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = $1`, table).Scan(&rls, &forced); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil || !rls || !forced || n != 0 {
			t.Fatalf("%s: rls=%v forced=%v rows=%d %v", table, rls, forced, n, err)
		}
	}
}
