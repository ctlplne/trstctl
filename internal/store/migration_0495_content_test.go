// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0495RetainsUnclassifiedDiscoveryHistory(t *testing.T) {
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, 495)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	applyMigrationFiles(t, ctx, pool, prefix)
	const tenant = "49500000-0000-4000-8000-000000000001"
	const source = "49500000-0000-4000-8000-000000000002"
	const run = "49500000-0000-4000-8000-000000000003"
	if _, err := pool.Exec(ctx, `INSERT INTO discovery_sources (tenant_id, id, kind, name, created_at, updated_at)
		VALUES ($1, $2, 'manual', 'fixture-source', now(), now())`, tenant, source); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO discovery_runs (tenant_id, id, source_id, status, error, created_at)
		VALUES ($1, $2, $3, 'failed', 'fixture-retained-detail', now())`, tenant, run, source); err != nil {
		t.Fatal(err)
	}
	const retained = `SELECT to_jsonb(r) - 'diagnostics_classified' FROM discovery_runs r
		WHERE tenant_id = '49500000-0000-4000-8000-000000000001' AND id = '49500000-0000-4000-8000-000000000003'`
	beforeCount, beforeDigest := checksumQuery(t, ctx, pool, retained)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if count, digest := checksumQuery(t, ctx, pool, retained); count != 1 || count != beforeCount || digest != beforeDigest {
		t.Fatal("migration changed a retained discovery completion")
	}
	var classified bool
	if err := pool.QueryRow(ctx, `SELECT diagnostics_classified FROM discovery_runs WHERE tenant_id = $1 AND id = $2`,
		tenant, run).Scan(&classified); err != nil || classified {
		t.Fatalf("historical discovery completion gained diagnostic authority: %v", err)
	}
}
