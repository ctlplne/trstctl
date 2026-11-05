// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0409PreservesTargetsAndAdmitsOnlyKnownTypes(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 409)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	const tenant = "40900000-0000-4000-8000-000000000001"
	insert := func(kind string) error {
		_, err := pool.Exec(ctx, `INSERT INTO pam_targets(tenant_id,target_type,id,registered_by,registered_at) VALUES($1,$2,$2,'operator','2026-11-05T12:00:00Z')`, tenant, kind)
		return err
	}
	for _, kind := range []string{"postgres", "ssh", "redis", "mysql", "mongodb", "clickhouse", "kubernetes", "snowflake", "aws", "gcp"} {
		if err := insert(kind); err != nil {
			t.Fatal(err)
		}
	}
	const query = `SELECT to_jsonb(t)::text FROM pam_targets t WHERE tenant_id='40900000-0000-4000-8000-000000000001' ORDER BY target_type,id`
	before, sum := checksumQuery(t, ctx, pool, query)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	after, afterSum := checksumQuery(t, ctx, pool, query)
	if before != 10 || after != 10 || sum != afterSum {
		t.Fatal("target upgrade changed previous tenant registrations")
	}
	if err := insert("azure"); err != nil {
		t.Fatalf("Azure registration still rejected: %v", err)
	}
	if err := insert("unknown-target-type"); err == nil {
		t.Fatal("migration admitted an unsupported protocol")
	}
}
