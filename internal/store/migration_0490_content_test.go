// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// X2-L7: 0490 records, with constant defaults, whether a crypto asset is a
// product's built-in default and whose default it is. Every asset recorded
// before it keeps its content and reads as a stated fact (config_source and
// product_version empty), as every host-config fact was.
func TestMigration0490KeepsCryptoAssetsAsStatedFacts(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 490)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "49000000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	seeds := []struct{ id, kind, location, protocol string }{
		{"49000000-0000-4000-8000-0000000000a1", "host-config", "/etc/haproxy/haproxy.cfg", "TLSv1.0"},
		{"49000000-0000-4000-8000-0000000000a2", "host-config", "/etc/ssl/openssl.cnf", "TLSv1.2"},
		{"49000000-0000-4000-8000-0000000000a3", "tls-endpoint", "app.example:443", "TLSv1.3"},
	}
	for i, seed := range seeds {
		if _, err := tx.Exec(ctx, `INSERT INTO crypto_assets
			        (id, tenant_id, signature, kind, location, protocol, library, strength,
			         quantum_vulnerable, reasons, created_at, event_sequence, is_active, import_source)
			 VALUES ($1, $2, $3, $4, $5, $6, 'haproxy', 'weak', false, '{"TLSv1.0 is below the TLSv1.2 minimum"}',
			         '2026-11-15T08:00:00Z', $7, $8, '')`,
			seed.id, tenant, seed.kind+"|"+seed.location+"|"+seed.protocol, seed.kind, seed.location, seed.protocol, i+10, i != 1); err != nil {
			t.Fatalf("seed a pre-0490 crypto asset: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const assets = `SELECT to_jsonb(a)::text FROM crypto_assets a ORDER BY id`
	count, sum := checksumQuery(t, ctx, pool, assets)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	const kept = `SELECT (to_jsonb(a) - 'config_source' - 'product_version')::text FROM crypto_assets a ORDER BY id`
	if n, after := checksumQuery(t, ctx, pool, kept); count != len(seeds) || n != count || after != sum {
		t.Fatalf("0490 changed crypto asset content: %d/%s before, %d/%s after", count, sum, n, after)
	}
	var defaults int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM crypto_assets WHERE config_source <> '' OR product_version <> ''`).Scan(&defaults); err != nil {
		t.Fatal(err)
	}
	if defaults != 0 {
		t.Fatalf("%d pre-0490 assets read as product defaults, want none", defaults)
	}
}
