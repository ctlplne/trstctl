// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0391KeepsSessionsWithoutAGatewayEnd is 0391's exact N-1 -> N
// case (A255): a session from before records no gateway end, and every
// pre-existing value is unchanged.
func TestMigration0391KeepsSessionsWithoutAGatewayEnd(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 391)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "39100000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO pam_sessions (tenant_id, id, target_type, target_id, role, status, subject, requested_by,
		        backend_ref, delivery, gateway_agent_id, gateway_ticket_digest, ssh_principal, started_at, expires_at,
		        revocation_requested_by, revocation_reason, revocation_requested_at)
		VALUES ($1, '39100000-0000-4000-8000-0000000000a1', 'ssh', 'bastion', 'user', 'revoking', 'alice', 'alice',
		        'bastion', 'gateway', '39100000-0000-4000-8000-0000000000b1', repeat('b', 64), 'alice',
		        '2026-11-04T08:00:00Z', '2026-11-04T09:00:00Z', 'op', 'incident', '2026-11-04T08:30:00Z')`, tenant); err != nil {
		t.Fatalf("seed a pre-0391 session: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const sessions = `SELECT (to_jsonb(o) - ARRAY['gateway_ended_at','gateway_ended'])::text FROM pam_sessions o ORDER BY id`
	before, beforeSum := checksumQuery(t, ctx, pool, sessions)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	if after, afterSum := checksumQuery(t, ctx, pool, sessions); before != 1 || after != before || afterSum != beforeSum {
		t.Fatalf("0391 changed session content: %d/%s before, %d/%s after", before, beforeSum, after, afterSum)
	}
	var ended int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_sessions WHERE gateway_ended_at IS NOT NULL OR gateway_ended <> ''`).Scan(&ended); err != nil {
		t.Fatal(err)
	}
	if ended != 0 {
		t.Fatalf("%d pre-0391 sessions gained a gateway end", ended)
	}
}
