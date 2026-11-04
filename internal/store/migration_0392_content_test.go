// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0392KeepsTargetsAndAdmitsRedis is 0392's exact N-1 -> N case
// (A256): existing PostgreSQL and SSH targets are unchanged, a Redis target
// is admitted, and a type the broker does not serve is still refused.
func TestMigration0392KeepsTargetsAndAdmitsRedis(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 392)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "39200000-0000-4000-8000-000000000001"
	insert := func(targetType, id string) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO pam_targets (tenant_id, target_type, id, provider_id, allowed_roles, registered_by, registered_at)
			VALUES ($1, $2, $3, 'provider', ARRAY['reader'], 'op', '2026-11-04T08:00:00Z')`, tenant, targetType, id); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	for _, seed := range [][2]string{{"postgres", "orders"}, {"ssh", "bastion"}} {
		if err := insert(seed[0], seed[1]); err != nil {
			t.Fatalf("seed a pre-0392 %s target: %v", seed[0], err)
		}
	}
	if err := insert("redis", "cache"); err == nil {
		t.Fatal("a Redis target was admitted before 0392")
	}
	const targets = `SELECT to_jsonb(o)::text FROM pam_targets o ORDER BY target_type, id`
	before, beforeSum := checksumQuery(t, ctx, pool, targets)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	if after, afterSum := checksumQuery(t, ctx, pool, targets); before != 2 || after != before || afterSum != beforeSum {
		t.Fatalf("0392 changed target content: %d/%s before, %d/%s after", before, beforeSum, after, afterSum)
	}
	if err := insert("redis", "cache"); err != nil {
		t.Fatalf("0392 does not admit a Redis target: %v", err)
	}
	if err := insert("mysql", "orders"); err == nil {
		t.Fatal("0392 admitted a target type the broker does not serve")
	}
	var checks int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conrelid = 'pam_targets'::regclass AND contype = 'c'
		AND pg_get_constraintdef(oid) LIKE '%target_type%'`).Scan(&checks); err != nil {
		t.Fatal(err)
	}
	if checks != 1 {
		t.Fatalf("pam_targets has %d target_type checks, want the one 0392 defines", checks)
	}
}
