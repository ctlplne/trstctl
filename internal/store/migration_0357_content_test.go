// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Q6: 0357 lets a decoy be a PostgreSQL login. Decoys from before it keep all
// their content and kind; a database decoy must name its provider, lease and
// login, and no other kind may.
func TestMigration0357KeepsDecoysAndAddsDatabaseDecoys(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 357)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "35700000-0000-4000-8000-000000000001"
	exec := func(sql string, args ...any) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err := exec(`INSERT INTO honey_tokens (id, tenant_id, kind, name, placement, token_hash, state, created_at,
		secret_name, trigger_subject, triggered_at)
		VALUES ('35700000-0000-4000-8000-0000000000a1', $1, 'secret', 'db password bait', 'repo', 'secret-decoy:a1',
		 'triggered', '2026-11-01T00:00:00Z', 'prod/db/password', 'ci-runner-7', '2026-11-01T01:00:00Z'),
		       ('35700000-0000-4000-8000-0000000000a2', $1, 'native', 'ci bait', 'repo:.env', 'aa11', 'active',
		 '2026-11-01T00:00:00Z', NULL, NULL, NULL)`, tenant); err != nil {
		t.Fatalf("seed pre-0357 decoys: %v", err)
	}
	const decoys = `SELECT id::text, kind, name, placement, token_hash, state, created_at, triggered_at,
		secret_name, trigger_subject FROM honey_tokens ORDER BY id`
	count, sum := checksumQuery(t, ctx, pool, decoys)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, after := checksumQuery(t, ctx, pool, decoys); count != 2 || n != count || after != sum {
		t.Fatalf("0357 changed decoys: %d/%s before, %d/%s after", count, sum, n, after)
	}
	if err := exec(`INSERT INTO honey_tokens (id, tenant_id, kind, name, placement, token_hash, state, created_at,
		db_provider_id, db_lease_id, db_role)
		VALUES ('35700000-0000-4000-8000-0000000000a3', $1, 'database', 'warehouse bait', 'wiki', 'database-decoy:a3',
		 'active', now(), 'warehouse-pg', 'lease-1', 'trstctl_app_0123456789')`, tenant); err != nil {
		t.Fatalf("a complete database decoy was refused: %v", err)
	}
	for name, sql := range map[string]string{
		"database decoy without a lease": `INSERT INTO honey_tokens (id, tenant_id, kind, name, placement, token_hash, state, created_at, db_provider_id, db_role)
			VALUES ('35700000-0000-4000-8000-0000000000a4', $1, 'database', 'x', 'y', 'database-decoy:a4', 'active', now(), 'p', 'r')`,
		"secret decoy naming a provider": `INSERT INTO honey_tokens (id, tenant_id, kind, name, placement, token_hash, state, created_at, secret_name, db_provider_id)
			VALUES ('35700000-0000-4000-8000-0000000000a5', $1, 'secret', 'x', 'y', 'secret-decoy:a5', 'active', now(), 'prod/x', 'p')`,
	} {
		if err := exec(sql, tenant); err == nil {
			t.Fatalf("0357 accepted %s", name)
		}
	}
}
