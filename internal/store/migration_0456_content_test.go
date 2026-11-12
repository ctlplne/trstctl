// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// X6-L3: 0456 records which CBOM import source last observed each crypto
// asset, with a constant default. Every asset recorded before it — scanned
// or imported — keeps its content and names no import source, so nothing
// is retired until an import reconciles its own source.
func TestMigration0456KeepsCryptoAssetsAndNamesNoImportSource(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 456)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "45600000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	seeds := []struct{ id, kind, location, algorithm string }{
		{"45600000-0000-4000-8000-0000000000a1", "imported-algorithm", "vendor:acme:algo-rsa", "RSA"},
		{"45600000-0000-4000-8000-0000000000a2", "imported-protocol", "vendor:acme:proto-tls", ""},
		{"45600000-0000-4000-8000-0000000000a3", "tls-endpoint", "app.example:443", "ECDHE"},
	}
	for i, seed := range seeds {
		if _, err := tx.Exec(ctx, `INSERT INTO crypto_assets
			        (id, tenant_id, signature, kind, location, algorithm, key_bits, library, strength,
			         quantum_vulnerable, reasons, created_at, event_sequence, is_active)
			 VALUES ($1, $2, $3, $4, $5, $6, 1024, 'openssl 1.1.1w', 'weak', true, '{"weak key"}',
			         '2026-11-12T08:00:00Z', $7, $8)`,
			seed.id, tenant, seed.kind+"|"+seed.location, seed.kind, seed.location, seed.algorithm, i+10, i != 1); err != nil {
			t.Fatalf("seed a pre-0456 crypto asset: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const assets = `SELECT to_jsonb(a)::text FROM crypto_assets a ORDER BY id`
	count, sum := checksumQuery(t, ctx, pool, assets)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	const kept = `SELECT (to_jsonb(a) - 'import_source')::text FROM crypto_assets a ORDER BY id`
	if n, after := checksumQuery(t, ctx, pool, kept); count != len(seeds) || n != count || after != sum {
		t.Fatalf("0456 changed crypto asset content: %d/%s before, %d/%s after", count, sum, n, after)
	}
	var named, inactive int
	if err := pool.QueryRow(ctx, `SELECT
		    (SELECT count(*) FROM crypto_assets WHERE import_source <> ''),
		    (SELECT count(*) FROM crypto_assets WHERE NOT is_active)`).Scan(&named, &inactive); err != nil {
		t.Fatal(err)
	}
	if named != 0 || inactive != 1 {
		t.Fatalf("pre-0456 assets: %d name an import source (want 0), %d inactive (want the 1 seeded)", named, inactive)
	}
}
