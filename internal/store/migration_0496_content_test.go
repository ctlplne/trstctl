// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0496KeepsHistoricalAttackPathMetadataUnverified(t *testing.T) {
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, 496)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	applyMigrationFiles(t, ctx, pool, prefix)
	const tenant = "49600000-0000-4000-8000-000000000001"
	const source = "49600000-0000-4000-8000-000000000002"
	const run = "49600000-0000-4000-8000-000000000003"
	const finding = "49600000-0000-4000-8000-000000000004"
	if _, err := pool.Exec(ctx, `INSERT INTO discovery_sources (tenant_id, id, kind, name, created_at, updated_at)
		VALUES ($1, $2, 'manual', 'fixture-source', now(), now())`, tenant, source); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO discovery_runs (tenant_id, id, source_id, status, created_at)
		VALUES ($1, $2, $3, 'succeeded', now())`, tenant, run, source); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO discovery_findings
		(tenant_id, id, run_id, source_id, kind, ref, provenance, metadata, discovered_at)
		VALUES ($1, $2, $3, $4, 'nhi-attack-path', 'fixture-ref', 'manual',
		'{"credential_refused_origin":"https://fixture.example.test"}', now())`, tenant, finding, run, source); err != nil {
		t.Fatal(err)
	}
	const retained = `SELECT to_jsonb(f) - 'attack_path_refused_origin' FROM discovery_findings f
		WHERE tenant_id = '49600000-0000-4000-8000-000000000001' AND id = '49600000-0000-4000-8000-000000000004'`
	beforeCount, beforeDigest := checksumQuery(t, ctx, pool, retained)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if count, digest := checksumQuery(t, ctx, pool, retained); count != 1 || count != beforeCount || digest != beforeDigest {
		t.Fatal("migration changed a retained discovery finding")
	}
	var origin string
	if err := pool.QueryRow(ctx, `SELECT attack_path_refused_origin FROM discovery_findings WHERE tenant_id = $1 AND id = $2`,
		tenant, finding).Scan(&origin); err != nil || origin != "" {
		t.Fatalf("historical discovery finding gained an observed origin: %v", err)
	}
}
