// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A156: 0351 lets an Intune poll schedule name an Entra app registration.
// Schedules from before it keep all their content and name none, so every
// existing token_ref stays a bearer reference.
func TestMigration0351KeepsMDMPollSchedulesAndStartsWithNoAppRegistration(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 351)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "35100000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mdm_poll_schedules
		(tenant_id, mdm, base_url, token_ref, filter, interval_seconds, enabled, allow_private_endpoint,
		 execution, renewal_window_days, required_agent_id, last_run_at, last_error)
		VALUES ($1, 'intune', 'https://graph.microsoft.com', 'secret://mdm/graph-token', 'operatingSystem eq ''iOS''',
		 3600, true, false, 'relay', 14, '35100000-0000-4000-8000-0000000000a1', '2026-10-30T00:00:00Z', '')`, tenant); err != nil {
		t.Fatalf("seed a pre-0351 schedule: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const schedules = `SELECT tenant_id::text, mdm, base_url, token_ref, filter, interval_seconds, enabled,
		allow_private_endpoint, execution, renewal_window_days, required_agent_id::text, last_run_at, last_error
		FROM mdm_poll_schedules ORDER BY mdm`
	count, sum := checksumQuery(t, ctx, pool, schedules)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, after := checksumQuery(t, ctx, pool, schedules); count != 1 || n != count || after != sum {
		t.Fatalf("0351 changed MDM poll schedules: %d/%s before, %d/%s after", count, sum, n, after)
	}
	var named int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM mdm_poll_schedules
		WHERE entra_authority <> '' OR entra_directory_tenant_id <> '' OR entra_client_id <> ''`).Scan(&named); err != nil {
		t.Fatal(err)
	}
	if named != 0 {
		t.Fatalf("after 0351 %d schedules name an app registration; want none", named)
	}
}
