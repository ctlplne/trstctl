// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// P5: 0360 admits syslog and Elasticsearch audit feeds; a syslog destination
// may omit its credential reference, every other provider still needs one,
// and existing destinations are unchanged.
func TestMigration0360KeepsFeedsAndAdmitsSyslogAndElastic(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 360)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "36000000-0000-4000-8000-000000000001"
	insert := func(id, provider, tokenRef string) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_feed_destinations
			(id, tenant_id, name, provider, endpoint_url, token_ref, interval_seconds, batch_size,
			 config_event_sequence, next_run_at, created_at, updated_at)
			VALUES ($1, $2, $5, $3, 'https://collector.example.test/x', $4, 300, 100, 1, now(), now(), now())`,
			id, tenant, provider, tokenRef, "feed-"+id); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err := insert("36000000-0000-4000-8000-0000000000a1", "splunk-hec", "env:SPLUNK"); err != nil {
		t.Fatalf("seed a pre-0360 feed: %v", err)
	}
	if err := insert("36000000-0000-4000-8000-0000000000a2", "syslog", "env:CA"); err == nil {
		t.Fatal("before 0360 a syslog feed was accepted")
	}
	const feeds = `SELECT id::text, provider, endpoint_url, token_ref, interval_seconds, batch_size FROM audit_feed_destinations ORDER BY id`
	count, sum := checksumQuery(t, ctx, pool, feeds)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, after := checksumQuery(t, ctx, pool, feeds); count != 1 || n != count || after != sum {
		t.Fatalf("0360 changed feeds: %d/%s before, %d/%s after", count, sum, n, after)
	}
	if err := insert("36000000-0000-4000-8000-0000000000a3", "syslog", ""); err != nil {
		t.Fatalf("0360 refused a syslog feed trusting the system roots: %v", err)
	}
	if err := insert("36000000-0000-4000-8000-0000000000a4", "elastic", "env:ES_API_KEY"); err != nil {
		t.Fatalf("0360 refused an elastic feed: %v", err)
	}
	if err := insert("36000000-0000-4000-8000-0000000000a5", "elastic", ""); err == nil {
		t.Fatal("0360 accepted an elastic feed without a credential reference")
	}
	if err := insert("36000000-0000-4000-8000-0000000000a6", "kafka", "env:K"); err == nil {
		t.Fatal("0360 accepted a provider trstctl does not deliver to")
	}
}
