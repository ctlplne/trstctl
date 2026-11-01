// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Q6: 0356 lets a decoy be a stored secret registered as bait. Bearer and AWS
// decoys from before it keep all their content and their kind; a secret decoy
// must name its secret, and no other kind may.
func TestMigration0356KeepsDecoysAndAddsSecretDecoys(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 356)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "35600000-0000-4000-8000-000000000001"
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
		triggered_at, trigger_method, trigger_path)
		VALUES ('35600000-0000-4000-8000-0000000000a1', $1, 'native', 'ci bait', 'repo:.env', 'aa11', 'triggered',
		 '2026-11-01T00:00:00Z', '2026-11-01T01:00:00Z', 'GET', '/api/v1/owners')`, tenant); err != nil {
		t.Fatalf("seed a pre-0356 bearer decoy: %v", err)
	}
	if err := exec(`INSERT INTO honey_tokens (id, tenant_id, kind, name, placement, token_hash, state, created_at,
		aws_account_config_id, aws_account_id, aws_access_key_id, aws_lease_id, aws_regions, aws_poll_interval_seconds)
		VALUES ('35600000-0000-4000-8000-0000000000a2', $1, 'aws', 'aws bait', 'wiki', 'bb22', 'active',
		 '2026-11-01T00:00:00Z', 'lab', '123456789012', 'AKIAEXAMPLE', 'lease-1', ARRAY['us-east-1'], 300)`, tenant); err != nil {
		t.Fatalf("seed a pre-0356 AWS decoy: %v", err)
	}
	const decoys = `SELECT id::text, kind, name, placement, token_hash, state, created_at, triggered_at,
		trigger_method, trigger_path, aws_account_id, aws_regions FROM honey_tokens ORDER BY id`
	count, sum := checksumQuery(t, ctx, pool, decoys)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, after := checksumQuery(t, ctx, pool, decoys); count != 2 || n != count || after != sum {
		t.Fatalf("0356 changed decoys: %d/%s before, %d/%s after", count, sum, n, after)
	}
	var named int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM honey_tokens WHERE secret_name IS NOT NULL OR trigger_subject IS NOT NULL`).Scan(&named); err != nil {
		t.Fatal(err)
	}
	if named != 0 {
		t.Fatalf("after 0356 %d existing decoys name a secret or a reader", named)
	}
	if err := exec(`INSERT INTO honey_tokens (id, tenant_id, kind, name, placement, token_hash, state, created_at, secret_name)
		VALUES ('35600000-0000-4000-8000-0000000000a3', $1, 'secret', 'db password bait', 'vault path', 'secret-decoy:a3',
		 'active', '2026-11-01T00:00:00Z', 'prod/db/password')`, tenant); err != nil {
		t.Fatalf("a secret decoy naming its secret was refused: %v", err)
	}
	for name, sql := range map[string]string{
		"secret decoy without a secret": `INSERT INTO honey_tokens (id, tenant_id, kind, name, placement, token_hash, state, created_at)
			VALUES ('35600000-0000-4000-8000-0000000000a4', $1, 'secret', 'x', 'y', 'secret-decoy:a4', 'active', now())`,
		"bearer decoy naming a secret": `INSERT INTO honey_tokens (id, tenant_id, kind, name, placement, token_hash, state, created_at, secret_name)
			VALUES ('35600000-0000-4000-8000-0000000000a5', $1, 'native', 'x', 'y', 'cc33', 'active', now(), 'prod/x')`,
		"unknown kind": `INSERT INTO honey_tokens (id, tenant_id, kind, name, placement, token_hash, state, created_at)
			VALUES ('35600000-0000-4000-8000-0000000000a6', $1, 'database', 'x', 'y', 'dd44', 'active', now())`,
	} {
		if err := exec(sql, tenant); err == nil {
			t.Fatalf("0356 accepted %s", name)
		}
	}
}
