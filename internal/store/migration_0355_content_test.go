// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// G1: 0355 lets a PAM session record the operation approval its activation
// consumed. Sessions from before it keep all their content and read no
// approval link ("not recorded"), never a guessed one.
func TestMigration0355KeepsPAMSessionsAndStartsWithoutAnApprovalLink(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 355)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "35500000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO pam_sessions
		(tenant_id, id, target_type, target_id, role, status, subject, requested_by, reason, idempotency_key,
		 audit, started_at, expires_at, ended_at, revocation_requested_by, revocation_reason)
		VALUES ($1, '35500000-0000-4000-8000-0000000000a1', 'postgres', 'pg-main', 'readonly', 'active',
		 'pam-workload', 'alice', 'incident triage', 'key-1', '{"role":"readonly"}', '2026-11-01T00:00:00Z',
		 '2026-11-01T00:05:00Z', NULL, '', ''),
		       ($1, '35500000-0000-4000-8000-0000000000a2', 'ssh', 'bastion', 'ops', 'revoked',
		 'ssh-workload', 'bob', 'maintenance', 'key-2', '{}', '2026-11-01T01:00:00Z',
		 '2026-11-01T01:05:00Z', '2026-11-01T01:02:00Z', 'carol', 'contained')`, tenant); err != nil {
		t.Fatalf("seed pre-0355 sessions: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const sessions = `SELECT tenant_id::text, id::text, target_type, target_id, role, status, subject, requested_by,
		reason, idempotency_key, audit::text, started_at, expires_at, ended_at, revocation_requested_by,
		revocation_reason FROM pam_sessions ORDER BY id`
	count, sum := checksumQuery(t, ctx, pool, sessions)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, after := checksumQuery(t, ctx, pool, sessions); count != 2 || n != count || after != sum {
		t.Fatalf("0355 changed PAM sessions: %d/%s before, %d/%s after", count, sum, n, after)
	}
	var linked int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_sessions WHERE approval_request_id <> ''`).Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if linked != 0 {
		t.Fatalf("after 0355 %d historical sessions claim an approval link; want none", linked)
	}
}
