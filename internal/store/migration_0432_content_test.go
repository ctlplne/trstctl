// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0432KeepsTemplatesWithoutFreshSignIn is 0432's exact N-1 -> N
// case (A277): a template saved before requires no fresh sign-in, every
// pre-existing value is unchanged, and a window outside 60-3600 seconds is
// refused.
func TestMigration0432KeepsTemplatesWithoutFreshSignIn(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 432)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	const tenant = "43200000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO pam_access_templates (tenant_id, id, name, reason, required_approvals, max_ttl_seconds, revision, saved_by, saved_at)
		VALUES ($1, '43200000-0000-4000-8000-000000000002', 'prod-dba', 'production change', 2, 900, 1, 'op', '2026-11-08T00:00:00Z')`, tenant); err != nil {
		t.Fatalf("seed a pre-0432 template: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const templates = `SELECT (to_jsonb(o) - 'reauthenticate_within_seconds')::text FROM pam_access_templates o ORDER BY id`
	before, sum := checksumQuery(t, ctx, pool, templates)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if after, afterSum := checksumQuery(t, ctx, pool, templates); before != 1 || after != before || afterSum != sum {
		t.Fatalf("0432 changed template content: %d/%s before, %d/%s after", before, sum, after, afterSum)
	}
	var fresh int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_access_templates WHERE reauthenticate_within_seconds <> 0`).Scan(&fresh); err != nil {
		t.Fatal(err)
	}
	if fresh != 0 {
		t.Fatalf("%d pre-0432 templates require a fresh sign-in", fresh)
	}
	for _, window := range []int{30, 3601, 300} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		tag, err := tx.Exec(ctx, `UPDATE pam_access_templates SET reauthenticate_within_seconds = $1`, window)
		_ = tx.Rollback(ctx)
		switch {
		case window == 300 && (err != nil || tag.RowsAffected() != 1):
			t.Fatalf("a five-minute window was refused: %v (%d rows)", err, tag.RowsAffected())
		case window != 300 && err == nil:
			t.Fatalf("a %d-second window was admitted", window)
		}
	}
}
