// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
)

func TestMigration0421PreservesRegistrationsAndIsolatesLocalSAMInventory(t *testing.T) {
	const stable = `SELECT to_jsonb(t)::text FROM pam_targets t ORDER BY tenant_id,target_type,id`
	runPopulatedDefaultMigrationHarness(t, 421, stable, func(ctx context.Context, pool *pgxpool.Pool) {
		for _, tenant := range []string{tenantA, tenantB} {
			if _, err := pool.Exec(ctx, `INSERT INTO pam_targets(tenant_id,target_type,id,registered_by,registered_at) VALUES($1,'ssh','owned-local-host','operator','2026-11-07T00:00:00Z')`, tenant); err != nil {
				t.Fatal(err)
			}
		}
	}, func(ctx context.Context, pool *pgxpool.Pool, _ int) {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM windows_local_account_scans`).Scan(&count); err != nil || count != 0 {
			t.Fatal("upgrade invented local-SAM inventory", err)
		}
		for _, tenant := range []string{tenantA, tenantB} {
			if _, err := pool.Exec(ctx, `INSERT INTO windows_local_account_scans(tenant_id,id,agent_id,intent,status,queued_by,queued_at,queued_event_id) VALUES($1,'42100000-0000-4000-8000-000000000001','42100000-0000-4000-8000-000000000002','{}','queued','operator',now(),'42100000-0000-4000-8000-000000000001')`, tenant); err != nil {
				t.Fatal(err)
			}
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err = tx.Exec(ctx, "SET LOCAL ROLE trstctl_app"); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenantA); err != nil {
			t.Fatal(err)
		}
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM windows_local_account_scans WHERE tenant_id=$1`, tenantB).Scan(&count); err != nil || count != 0 {
			t.Fatal("local-SAM metadata crossed forced RLS", err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO windows_local_account_scans(tenant_id,id,agent_id,intent,status,queued_by,queued_at,queued_event_id) VALUES($1,'42100000-0000-4000-8000-000000000003','42100000-0000-4000-8000-000000000002','{}','queued','operator',now(),'42100000-0000-4000-8000-000000000003')`, tenantB); err == nil {
			t.Fatal("foreign local-SAM write bypassed forced RLS")
		}
	})
}
