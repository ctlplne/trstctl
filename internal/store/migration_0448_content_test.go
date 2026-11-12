// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0448KeepsSessionsWithoutAccountRotation is 0448's exact N-1 ->
// N case (A273-O4): a web console session opened before it keeps every value,
// names no account rotation provider and has no queued rotation, so the
// expiry worker never rotates an account for it.
func TestMigration0448KeepsSessionsWithoutAccountRotation(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 448)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "44800000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO pam_sessions (tenant_id, id, target_type, target_id, role, status, subject, requested_by,
		        backend_ref, delivery, gateway_agent_id, gateway_ticket_digest, started_at, expires_at, ended_at, web_sign_in)
		VALUES ($1, '44800000-0000-4000-8000-0000000000a1', 'webconsole', 'bmc-console', 'bmc/ops', 'expired',
		        'alice', 'alice', 'vaulted:bmc/ops', 'gateway', '44800000-0000-4000-8000-0000000000b1',
		        repeat('a', 64), '2026-11-12T08:00:00Z', '2026-11-12T09:00:00Z', '2026-11-12T09:00:00Z', '{"mode":"basic"}')`, tenant); err != nil {
		t.Fatalf("seed a pre-0448 web console session: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const sessions = `SELECT to_jsonb(o)::text FROM pam_sessions o ORDER BY id`
	count, sum := checksumQuery(t, ctx, pool, sessions)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	const kept = `SELECT (to_jsonb(o) - 'account_rotation_provider' - 'account_rotation_command_id')::text FROM pam_sessions o ORDER BY id`
	if n, after := checksumQuery(t, ctx, pool, kept); count != 1 || n != count || after != sum {
		t.Fatalf("0448 changed session content: %d/%s before, %d/%s after", count, sum, n, after)
	}
	var due int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_sessions WHERE account_rotation_provider <> '' OR account_rotation_command_id <> ''`).Scan(&due); err != nil {
		t.Fatal(err)
	}
	if due != 0 {
		t.Fatalf("%d pre-0448 sessions gained an account rotation", due)
	}
}
