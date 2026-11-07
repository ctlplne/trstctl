// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0424KeepsTemplatesWithoutClipboard is 0424's exact N-1 -> N
// case (A269): a template saved before allows no desktop clipboard, and every
// pre-existing value is unchanged.
func TestMigration0424KeepsTemplatesWithoutClipboard(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 424)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	const tenant = "42400000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO pam_access_templates (tenant_id, id, name, reason, required_approvals, max_ttl_seconds, revision, saved_by, saved_at)
		VALUES ($1, '42400000-0000-4000-8000-000000000002', 'desktop-support', 'remote support', 2, 900, 1, 'op', '2026-11-07T12:00:00Z')`, tenant); err != nil {
		t.Fatalf("seed a pre-0424 template: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const templates = `SELECT (to_jsonb(o) - 'desktop_clipboard')::text FROM pam_access_templates o ORDER BY id`
	before, sum := checksumQuery(t, ctx, pool, templates)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if after, afterSum := checksumQuery(t, ctx, pool, templates); before != 1 || after != before || afterSum != sum {
		t.Fatalf("0424 changed template content: %d/%s before, %d/%s after", before, sum, after, afterSum)
	}
	var allowed int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_access_templates WHERE desktop_clipboard <> 'deny'`).Scan(&allowed); err != nil {
		t.Fatal(err)
	}
	if allowed != 0 {
		t.Fatalf("%d pre-0424 templates allow a desktop clipboard", allowed)
	}
}
