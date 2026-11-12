// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// P5-L4: 0452 adds audit_feed_destinations.auth_scheme with an empty default.
// Every feed configured before it keeps its content and reads no scheme, which
// an Elasticsearch feed takes as an API key, as it always sent.
func TestMigration0452KeepsFeedsAndStartsWithNoAuthScheme(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 452)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "45200000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	for i, provider := range []string{"elastic", "syslog", "splunk-hec"} {
		if _, err := tx.Exec(ctx, `INSERT INTO audit_feed_destinations
			        (id, tenant_id, name, provider, endpoint_url, token_ref, interval_seconds, batch_size,
			         config_event_sequence, next_run_at, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, 'https://collector.example.test/x', 'env:TOKEN', 300, 100, $5,
			         '2026-11-12T08:00:00Z', '2026-11-12T08:00:00Z', '2026-11-12T08:00:00Z')`,
			"45200000-0000-4000-8000-0000000000a"+string(rune('1'+i)), tenant, "feed "+provider, provider, 10+i); err != nil {
			t.Fatalf("seed a pre-0452 %s feed: %v", provider, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const feeds = `SELECT to_jsonb(f)::text FROM audit_feed_destinations f ORDER BY id`
	count, sum := checksumQuery(t, ctx, pool, feeds)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	const kept = `SELECT (to_jsonb(f) - 'auth_scheme')::text FROM audit_feed_destinations f ORDER BY id`
	if n, after := checksumQuery(t, ctx, pool, kept); count != 3 || n != count || after != sum {
		t.Fatalf("0452 changed feed content: %d/%s before, %d/%s after", count, sum, n, after)
	}
	var schemed int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_feed_destinations WHERE auth_scheme <> ''`).Scan(&schemed); err != nil {
		t.Fatal(err)
	}
	if schemed != 0 {
		t.Fatalf("%d pre-0452 feeds gained an auth scheme", schemed)
	}
}
