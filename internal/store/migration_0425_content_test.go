// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0425PreservesTargetsAndAdmitsNetDevice is 0425's exact
// N-1 -> N case (A270): every registered target is unchanged, a netdevice
// target is admitted, and an unknown type is still refused.
func TestMigration0425PreservesTargetsAndAdmitsNetDevice(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 425)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	const tenant = "42500000-0000-4000-8000-000000000001"
	insert := func(kind string) error {
		_, err := pool.Exec(ctx, `INSERT INTO pam_targets(tenant_id,target_type,id,registered_by,registered_at) VALUES($1,$2,$2,'operator','2026-11-07T12:00:00Z')`, tenant, kind)
		return err
	}
	kinds := []string{"postgres", "ssh", "redis", "mysql", "mongodb", "clickhouse", "kubernetes", "snowflake", "aws", "gcp", "azure", "aws-console", "rdp", "windows_local"}
	for _, kind := range kinds {
		if err := insert(kind); err != nil {
			t.Fatal(err)
		}
	}
	if err := insert("netdevice"); err == nil {
		t.Fatal("the pre-0425 schema admitted netdevice")
	}
	const query = `SELECT to_jsonb(t)::text FROM pam_targets t WHERE tenant_id='42500000-0000-4000-8000-000000000001' ORDER BY target_type,id`
	before, sum := checksumQuery(t, ctx, pool, query)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	after, afterSum := checksumQuery(t, ctx, pool, query)
	if before != len(kinds) || after != len(kinds) || sum != afterSum {
		t.Fatal("0425 changed previous tenant registrations")
	}
	if err := insert("netdevice"); err != nil {
		t.Fatalf("netdevice registration still rejected: %v", err)
	}
	if err := insert("unknown-target-type"); err == nil {
		t.Fatal("0425 admitted an unsupported target type")
	}
}
