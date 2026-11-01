// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Q1: 0358 lets an access review record what it did. Items from before it keep
// all their content and start with no outcome and no next review date; an
// outcome must be one trstctl records.
func TestMigration0358KeepsReviewItemsAndStartsWithNoOutcome(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 358)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "35800000-0000-4000-8000-000000000001"
	exec := func(sql string, args ...any) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err := exec(`INSERT INTO nhi_access_review_campaigns (tenant_id, id, name, reviewer_subject, requested_by, status,
		item_count, pending_count, revoked_count)
		VALUES ($1, '35800000-0000-4000-8000-0000000000c1', 'q4 review', 'bob@example.test', 'alice@example.test', 'open', 2, 1, 1)`,
		tenant); err != nil {
		t.Fatalf("seed pre-0358 campaign: %v", err)
	}
	if err := exec(`INSERT INTO nhi_access_review_items (tenant_id, campaign_id, item_id, nhi_id, nhi_kind, display_name,
		owner_ref, resource, entitlement, evidence_refs, status, decision_by, decision_reason, decided_at)
		VALUES ($1, '35800000-0000-4000-8000-0000000000c1', '35800000-0000-4000-8000-0000000000a1', 'token:t1', 'api_token',
		 'ci token', 'person:alice', 'res:trstctl-api', 'certs:read', '{graph:holder:person:alice}', 'revoked',
		 'bob@example.test', 'unused', '2026-11-01T00:00:00Z'),
		       ($1, '35800000-0000-4000-8000-0000000000c1', '35800000-0000-4000-8000-0000000000a2', 'pam:p1', 'pam_session',
		 'app_ro@pg-main', '', 'res:pam:postgres:pg-main', 'app_ro', '{}', 'pending', '', '', NULL)`, tenant); err != nil {
		t.Fatalf("seed pre-0358 items: %v", err)
	}
	const items = `SELECT item_id::text, nhi_id, nhi_kind, display_name, owner_ref, resource, entitlement, risk,
		evidence_refs, status, decision_by, decision_reason, decided_at, created_at, updated_at
		FROM nhi_access_review_items ORDER BY item_id`
	count, sum := checksumQuery(t, ctx, pool, items)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, after := checksumQuery(t, ctx, pool, items); count != 2 || n != count || after != sum {
		t.Fatalf("0358 changed review items: %d/%s before, %d/%s after", count, sum, n, after)
	}
	var outcomes int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM nhi_access_review_items
		WHERE revocation_status <> '' OR revocation_detail <> '' OR revocation_requested_at IS NOT NULL
		   OR closed_at IS NOT NULL OR closing_evidence <> '' OR next_review_at IS NOT NULL`).Scan(&outcomes); err != nil {
		t.Fatal(err)
	}
	if outcomes != 0 {
		t.Fatalf("%d pre-0358 items gained an outcome or a next review date", outcomes)
	}
	if err := exec(`UPDATE nhi_access_review_items SET revocation_status = 'requested' WHERE item_id = '35800000-0000-4000-8000-0000000000a1'`); err != nil {
		t.Fatalf("a recorded outcome was refused: %v", err)
	}
	if err := exec(`UPDATE nhi_access_review_items SET revocation_status = 'done' WHERE item_id = '35800000-0000-4000-8000-0000000000a1'`); err == nil {
		t.Fatal("0358 accepted an outcome trstctl never records")
	}
}
