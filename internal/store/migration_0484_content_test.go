// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0484KeepsEmergencyGrantsNamingNoApprovers is 0484's N-1 -> N
// content case (A258-L2): every emergency grant opened before it keeps its
// values exactly and names no notified approver, since none was addressed by
// name when it opened.
func TestMigration0484KeepsEmergencyGrantsNamingNoApprovers(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 484)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "48400000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	for _, seed := range []string{
		`INSERT INTO pam_emergency_grants (tenant_id, session_id, responder, reason, target_type, target_id, role, opened_at, expires_at, review_status)
		 VALUES ($1, '48400000-0000-4000-8000-0000000000e1', 'oncall-ana', 'payments down', 'postgres', 'pg-main', 'readonly',
		 '2026-11-13T00:00:00Z', '2026-11-13T01:00:00Z', 'pending')`,
		`INSERT INTO pam_emergency_grants (tenant_id, session_id, responder, reason, target_type, target_id, role, opened_at, expires_at,
		 review_status, reviewer, review_outcome, review_notes, reviewed_at)
		 VALUES ($1, '48400000-0000-4000-8000-0000000000e2', 'oncall-ben', 'disk full', 'ssh', 'web-1', 'admin',
		 '2026-11-12T00:00:00Z', '2026-11-12T00:30:00Z', 'reviewed', 'lead-cy', 'justified', 'cleared the log volume', '2026-11-12T02:00:00Z')`,
	} {
		if _, err := tx.Exec(ctx, seed, tenant); err != nil {
			t.Fatalf("seed a pre-0484 emergency grant: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const rows = `SELECT tenant_id::text, session_id::text, responder, reason, target_type, target_id, role, opened_at, expires_at,
		review_status, reviewer, review_outcome, review_notes, reviewed_at
		FROM pam_emergency_grants ORDER BY session_id`
	count, sum := checksumQuery(t, ctx, pool, rows)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, after := checksumQuery(t, ctx, pool, rows); count != 2 || n != count || after != sum {
		t.Fatalf("0484 changed emergency grants: %d/%s before, %d/%s after", count, sum, n, after)
	}
	var naming int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_emergency_grants WHERE cardinality(notified_approvers) > 0`).Scan(&naming); err != nil {
		t.Fatal(err)
	}
	if naming != 0 {
		t.Fatalf("after 0484, %d earlier grants name notified approvers; want none", naming)
	}
}
