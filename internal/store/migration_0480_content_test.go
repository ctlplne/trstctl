// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// P12-L1: 0480 lets a factory batch pin device attestation roots and records
// each birth's attestation. Batches and births from before it keep all their
// content, pin no roots and count no unattested births, so they keep
// enrolling as before.
func TestMigration0480KeepsFactoryBatchesWithoutDeviceAttestation(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 480)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "48000000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	for _, seed := range []string{
		`INSERT INTO factory_batches (tenant_id, id, delegation_id, label, quota, birth_ttl_seconds, operational_profile,
		 created_by, created_at, event_sequence, recorded, over_quota)
		 VALUES ($1, '48000000-0000-4000-8000-0000000000b1', 'delegation-1', 'lot 7', 2, 3600, '', 'operator',
		 '2026-11-13T00:00:00Z', 7, 1, 0)`,
		`INSERT INTO factory_birth_certificates (tenant_id, batch_id, serial, device_name, fingerprint, certificate_der, not_after,
		 over_quota, recorded_at, event_sequence)
		 VALUES ($1, '48000000-0000-4000-8000-0000000000b1', '0a', 'sn-0001.devices.example.test', 'ab', '\x3082', '2026-11-14T00:00:00Z',
		 false, '2026-11-13T01:00:00Z', 8)`,
	} {
		if _, err := tx.Exec(ctx, seed, tenant); err != nil {
			t.Fatalf("seed a pre-0480 batch: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const rows = `SELECT b.tenant_id::text, b.id::text, b.delegation_id, b.label, b.quota, b.birth_ttl_seconds, b.created_by, b.created_at,
		b.recorded, b.over_quota, c.serial, c.device_name, c.fingerprint, c.certificate_der, c.not_after, c.over_quota, c.recorded_at
		FROM factory_batches b JOIN factory_birth_certificates c ON c.tenant_id = b.tenant_id AND c.batch_id = b.id ORDER BY c.serial`
	count, sum := checksumQuery(t, ctx, pool, rows)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, after := checksumQuery(t, ctx, pool, rows); count != 1 || n != count || after != sum {
		t.Fatalf("0480 changed factory batches or births: %d/%s before, %d/%s after", count, sum, n, after)
	}
	var pinned, unattested, attested int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE cardinality(device_attestation_roots) > 0), coalesce(sum(unattested), 0)
		FROM factory_batches`).Scan(&pinned, &unattested); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM factory_birth_certificates WHERE attestation <> ''`).Scan(&attested); err != nil {
		t.Fatal(err)
	}
	if pinned != 0 || unattested != 0 || attested != 0 {
		t.Fatalf("after 0480: %d batches pin roots, %d unattested, %d births with an attestation; want none", pinned, unattested, attested)
	}
}
