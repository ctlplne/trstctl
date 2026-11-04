// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 0383 adds the trail log files the decoy monitor read and, on each recorded
// decoy use, the accounts, CloudTrail category and where it was found (N4).
// Uses from before keep every value they had, name no accounts or category,
// and read as found by LookupEvents; no trail file is recorded.
func TestMigration0383KeepsDecoyUsesAsFoundByLookup(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 383)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant, decoy = "38300000-0000-4000-8000-000000000001", "38300000-0000-4000-8000-0000000000aa"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	seed := func(statement string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, statement, args...); err != nil {
			t.Fatalf("seed a pre-0383 decoy use: %v", err)
		}
	}
	seed(`INSERT INTO honey_tokens (id, tenant_id, kind, name, placement, token_hash, state, created_at,
		       aws_account_config_id, aws_account_id, aws_access_key_id, aws_lease_id, aws_regions, aws_poll_interval_seconds)
		VALUES ($1, $2, 'aws', 'bait', 'qa/trap', 'hash-0383', 'triggered', '2026-11-04T08:00:00Z',
		        'qa-aws', '123456789012', 'AKIADECOY00000001', 'lease-0383', ARRAY['us-east-1'], 60)`, decoy, tenant)
	seed(`INSERT INTO aws_honey_uses (tenant_id, honey_id, event_id, region, event_source, event_name,
		       source_ip_address, user_agent, error_code, event_time, detected_at)
		VALUES ($1, $2, 'ev-0383', 'us-east-1', 'sts.amazonaws.com', 'GetCallerIdentity', '203.0.113.7',
		        'aws-cli/2.18', 'AccessDenied', '2026-11-04T08:10:00Z', '2026-11-04T08:12:00Z')`, tenant, decoy)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const stable = `SELECT tenant_id::text, honey_id::text, event_id, region, event_source, event_name,
		source_ip_address, user_agent, error_code, event_time, detected_at FROM aws_honey_uses ORDER BY event_id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if beforeCount != 1 || afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0383 changed decoy uses: %d/%s before, %d/%s after", beforeCount, beforeChecksum, afterCount, afterChecksum)
	}
	var account, recipient, category, foundIn string
	if err := pool.QueryRow(ctx, `SELECT account_id, recipient_account_id, event_category, found_in FROM aws_honey_uses`).
		Scan(&account, &recipient, &category, &foundIn); err != nil {
		t.Fatal(err)
	}
	if account != "" || recipient != "" || category != "" || foundIn != "lookup" {
		t.Fatalf("a pre-0383 use reads %q %q %q %q, want no accounts or category, found by lookup", account, recipient, category, foundIn)
	}
	var files int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM aws_honey_trail_objects`).Scan(&files); err != nil || files != 0 {
		t.Fatalf("0383 starts with %d trail files (%v), want none", files, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE aws_honey_uses SET found_in = 'guess'`); err == nil {
		t.Fatal("0383 accepted a use found neither by lookup nor in a trail")
	}
}
