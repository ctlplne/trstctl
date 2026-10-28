// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
)

func TestMigrations0345Through0347PreserveDefaultIntakeCursors(t *testing.T) {
	ctx := context.Background()
	prefix, expand := splitMigrationsAtVersion(t, 345)
	_, index := splitMigrationsAtVersion(t, 346)
	_, attach := splitMigrationsAtVersion(t, 347)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	const tenant = "a2250000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ticket_intake_schedules (tenant_id,system,instance_url,token_ref,sn_table,query,subject_field,profile_field,interval_seconds,enabled,current_sweep_id,sweep_started_at,last_attempt_at,cursor,read_count,pages_completed,eligible_count,last_error) VALUES ($1,'servicenow','https://tickets.example.test','secret://itsm/intake','incident','state=1','u_subject','u_profile',3600,true,'a2250000-0000-4000-8000-000000000002','2026-10-28T00:00:00Z','2026-10-28T00:00:00Z','row100',100,1,100,'timeout')`, tenant); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const oldContent = `SELECT tenant_id::text,system,instance_url,token_ref,sn_table,jira_project,query,subject_field,profile_field,requester_field,justification_field,interval_seconds,enabled,allow_private_endpoint,private_egress_cidrs,last_run_at,last_error,current_sweep_id::text,sweep_started_at,last_attempt_at,cursor,read_count,expected_count,pages_completed,coverage_complete,eligible_count,skipped_count,updated_at FROM ticket_intake_schedules WHERE tenant_id='a2250000-0000-4000-8000-000000000001' ORDER BY system`
	beforeCount, beforeDigest := checksumQuery(t, ctx, pool, oldContent)
	applyMigrationFiles(t, ctx, pool, []migrationFile{expand, index, attach})
	afterCount, afterDigest := checksumQuery(t, ctx, pool, oldContent)
	if beforeCount != 1 || afterCount != beforeCount || beforeDigest != afterDigest {
		t.Fatalf("existing intake changed: %d/%s -> %d/%s", beforeCount, beforeDigest, afterCount, afterDigest)
	}
	var name, ownerField string
	if err = pool.QueryRow(ctx, `SELECT name,owner_field FROM ticket_intake_schedules WHERE tenant_id=$1 AND system='servicenow'`, tenant).Scan(&name, &ownerField); err != nil {
		t.Fatal(err)
	}
	if name != "default" || ownerField != "" {
		t.Fatalf("legacy defaults %q/%q", name, ownerField)
	}
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ticket_intake_schedules (tenant_id,system,name,instance_url,token_ref,sn_table,subject_field,profile_field,interval_seconds) VALUES ($1,'servicenow','requests','https://tickets.example.test','secret://itsm/intake','sc_req_item','u_subject','u_profile',3600)`, tenant); err != nil {
		t.Fatalf("new named schedule conflicts with retained default: %v", err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
