// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0427PreservesTargetsAndAdmitsBreakGlass is 0427's exact
// N-1 -> N case (A272): every registered target is unchanged, a breakglass
// target is admitted, and an unknown type is still refused.
func TestMigration0427PreservesTargetsAndAdmitsBreakGlass(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 427)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	const tenant = "42700000-0000-4000-8000-000000000001"
	insert := func(kind string) error {
		_, err := pool.Exec(ctx, `INSERT INTO pam_targets(tenant_id,target_type,id,registered_by,registered_at) VALUES($1,$2,$2,'operator','2026-11-07T12:00:00Z')`, tenant, kind)
		return err
	}
	kinds := []string{"postgres", "ssh", "redis", "mysql", "mongodb", "clickhouse", "kubernetes", "snowflake", "aws", "gcp", "azure", "aws-console", "rdp", "windows_local", "netdevice", "account"}
	for _, kind := range kinds {
		if err := insert(kind); err != nil {
			t.Fatal(err)
		}
	}
	if err := insert("breakglass"); err == nil {
		t.Fatal("the pre-0427 schema admitted breakglass")
	}
	const query = `SELECT to_jsonb(t)::text FROM pam_targets t WHERE tenant_id='42700000-0000-4000-8000-000000000001' ORDER BY target_type,id`
	before, sum := checksumQuery(t, ctx, pool, query)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	after, afterSum := checksumQuery(t, ctx, pool, query)
	if before != len(kinds) || after != len(kinds) || sum != afterSum {
		t.Fatal("0427 changed previous tenant registrations")
	}
	if err := insert("breakglass"); err != nil {
		t.Fatalf("breakglass registration still rejected: %v", err)
	}
	if err := insert("unknown-target-type"); err == nil {
		t.Fatal("0427 admitted an unsupported target type")
	}
}
