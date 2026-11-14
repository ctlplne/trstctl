// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// N9-L1: 0478 lets a Jamf poll schedule read the mobile device inventory.
// Schedules from before it keep all their content, and none reads mobile
// devices, so an API role that can read only computers keeps working.
func TestMigration0478KeepsMDMPollSchedulesReadingComputersOnly(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 478)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "47800000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	for _, seed := range []string{
		`INSERT INTO mdm_poll_schedules
		(tenant_id, mdm, base_url, token_ref, filter, interval_seconds, enabled, allow_private_endpoint,
		 execution, renewal_window_days, required_agent_id, last_run_at, last_error, jamf_client_id)
		VALUES ($1, 'jamf', 'https://jamf.example.test', 'secret://mdm/jamf-client-secret', '',
		 3600, true, false, 'relay', 14, '47800000-0000-4000-8000-0000000000a1', '2026-11-13T00:00:00Z', '',
		 '47800000-0000-4000-8000-0000000000c1')`,
		`INSERT INTO mdm_poll_schedules
		(tenant_id, mdm, base_url, token_ref, filter, interval_seconds, enabled, allow_private_endpoint,
		 execution, renewal_window_days, required_agent_id, last_run_at, last_error,
		 entra_authority, entra_directory_tenant_id, entra_client_id)
		VALUES ($1, 'intune', 'https://graph.microsoft.com', 'secret://mdm/entra-secret', '',
		 3600, true, false, 'relay', 0, '47800000-0000-4000-8000-0000000000a2', NULL, 'last read refused',
		 'https://login.microsoftonline.com', 'contoso.example', '47800000-0000-4000-8000-0000000000c2')`,
	} {
		if _, err := tx.Exec(ctx, seed, tenant); err != nil {
			t.Fatalf("seed a pre-0478 schedule: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const schedules = `SELECT tenant_id::text, mdm, base_url, token_ref, filter, interval_seconds, enabled,
		allow_private_endpoint, execution, renewal_window_days, required_agent_id::text, last_run_at, last_error,
		entra_authority, entra_directory_tenant_id, entra_client_id, jamf_client_id
		FROM mdm_poll_schedules ORDER BY mdm`
	count, sum := checksumQuery(t, ctx, pool, schedules)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, after := checksumQuery(t, ctx, pool, schedules); count != 2 || n != count || after != sum {
		t.Fatalf("0478 changed MDM poll schedules: %d/%s before, %d/%s after", count, sum, n, after)
	}
	var mobile int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM mdm_poll_schedules WHERE jamf_mobile_devices`).Scan(&mobile); err != nil {
		t.Fatal(err)
	}
	if mobile != 0 {
		t.Fatalf("after 0478 %d schedules read mobile devices; want none", mobile)
	}
}
