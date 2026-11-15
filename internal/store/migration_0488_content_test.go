// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0488KeepsEveryReplayRecordAtItsOneUse is 0488's N-1 -> N
// content case (M4-L4): every single-use record from before keeps its values
// and counts one use, the use that created it, so each earlier token keeps
// the single use it had.
func TestMigration0488KeepsEveryReplayRecordAtItsOneUse(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 488)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "48800000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	for _, seed := range []string{
		`INSERT INTO machine_credential_replays (tenant_id, method, key_digest, expires_at, used_at)
		 VALUES ($1, 'kubernetes', 'sha256:live', '2026-11-15T01:00:00Z', '2026-11-15T00:55:00Z')`,
		`INSERT INTO machine_credential_replays (tenant_id, method, key_digest, expires_at, used_at)
		 VALUES ($1, 'oidc', 'sha256:expired', '2026-11-14T01:00:00Z', '2026-11-14T00:30:00Z')`,
	} {
		if _, err := tx.Exec(ctx, seed, tenant); err != nil {
			t.Fatalf("seed a pre-0488 replay record: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const rows = `SELECT tenant_id::text, method, key_digest, expires_at, used_at FROM machine_credential_replays ORDER BY method, key_digest`
	count, sum := checksumQuery(t, ctx, pool, rows)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, after := checksumQuery(t, ctx, pool, rows); count != 2 || n != count || after != sum {
		t.Fatalf("0488 changed replay records: %d/%s before, %d/%s after", count, sum, n, after)
	}
	var other int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM machine_credential_replays WHERE uses <> 1`).Scan(&other); err != nil {
		t.Fatal(err)
	}
	if other != 0 {
		t.Fatalf("after 0488, %d earlier records count other than one use", other)
	}
}
