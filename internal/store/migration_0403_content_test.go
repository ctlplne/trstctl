// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0403KeepsTargetsOutOfFoldersAndTemplatesUnrecorded is 0403's
// exact N-1 -> N case (A261 part 3): a target registered before is in no
// folder and a template saved before requires no recording, and every
// pre-existing value is unchanged.
func TestMigration0403KeepsTargetsOutOfFoldersAndTemplatesUnrecorded(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 403)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "40300000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO pam_targets (tenant_id, target_type, id, provider_id, allowed_roles, enabled, registered_by, registered_at)
		VALUES ($1, 'postgres', 'orders-db', 'orders-pg', ARRAY['readonly'], true, 'op', '2026-11-05T01:00:00Z')`, tenant); err != nil {
		t.Fatalf("seed a pre-0403 target: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO pam_access_templates (tenant_id, id, name, reason, required_approvals, max_ttl_seconds, revision, saved_by, saved_at)
		VALUES ($1, '40300000-0000-4000-8000-000000000002', 'change-window', 'planned change', 2, 900, 1, 'op', '2026-11-05T01:00:00Z')`, tenant); err != nil {
		t.Fatalf("seed a pre-0403 template: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const targets = `SELECT (to_jsonb(o) - 'folder')::text FROM pam_targets o ORDER BY id`
	const templates = `SELECT (to_jsonb(o) - 'require_recording')::text FROM pam_access_templates o ORDER BY id`
	beforeTargets, beforeTargetsSum := checksumQuery(t, ctx, pool, targets)
	beforeTemplates, beforeTemplatesSum := checksumQuery(t, ctx, pool, templates)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	if after, afterSum := checksumQuery(t, ctx, pool, targets); beforeTargets != 1 || after != beforeTargets || afterSum != beforeTargetsSum {
		t.Fatalf("0403 changed target content: %d/%s before, %d/%s after", beforeTargets, beforeTargetsSum, after, afterSum)
	}
	if after, afterSum := checksumQuery(t, ctx, pool, templates); beforeTemplates != 1 || after != beforeTemplates || afterSum != beforeTemplatesSum {
		t.Fatalf("0403 changed template content: %d/%s before, %d/%s after", beforeTemplates, beforeTemplatesSum, after, afterSum)
	}
	var inFolder, recorded int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_targets WHERE folder <> ''`).Scan(&inFolder); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_access_templates WHERE require_recording`).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if inFolder != 0 || recorded != 0 {
		t.Fatalf("pre-0403 rows changed meaning: %d targets in a folder, %d templates requiring recording", inFolder, recorded)
	}
}
