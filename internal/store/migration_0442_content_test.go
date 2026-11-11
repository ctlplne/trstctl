// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 0442 adds the bot scopes a Slack workspace granted (N8-L1). An install from
// before keeps every value it had and claims no scope: its install event
// recorded none, so it does not check the approval channel before posting
// until it is installed again.
func TestMigration0442KeepsSlackInstallsWithNoScopes(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 442)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "44200000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO slack_installs
		       (tenant_id, team_id, team_name, bot_user_id, app_id, sealed_bot_token, approval_channel_id,
		        approval_channel_name, installed_by, installed_at, updated_at, event_sequence)
		VALUES ($1, 'T0442TEAM', 'Workspace 0442', 'U0442BOT', 'A0442', 'sealed-0442'::bytea, 'C0442',
		        'approvals-0442', 'admin-0442@example.test', '2026-11-04T10:00:00Z', '2026-11-04T10:05:00Z', 4420)`, tenant); err != nil {
		t.Fatalf("seed a pre-0442 install: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const stable = `SELECT tenant_id::text, team_id, team_name, bot_user_id, app_id, sealed_bot_token, approval_channel_id,
		approval_channel_name, installed_by, installed_at, updated_at, event_sequence
		FROM slack_installs ORDER BY tenant_id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if beforeCount != 1 || afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0442 changed install content: %d/%s before, %d/%s after", beforeCount, beforeChecksum, afterCount, afterChecksum)
	}
	var scoped int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM slack_installs WHERE scopes <> ''`).Scan(&scoped); err != nil {
		t.Fatal(err)
	}
	if scoped != 0 {
		t.Fatalf("%d pre-0442 installs claim granted scopes, want none", scoped)
	}
}
