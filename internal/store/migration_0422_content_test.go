// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
)

func TestMigration0422PreservesRegistrationsAndIsolatesNativeHostGenerations(t *testing.T) {
	const stable = `SELECT to_jsonb(t)::text FROM pam_targets t ORDER BY tenant_id,target_type,id`
	runPopulatedDefaultMigrationHarness(t, 422, stable, func(ctx context.Context, pool *pgxpool.Pool) {
		for _, tenant := range []string{tenantA, tenantB} {
			if _, err := pool.Exec(ctx, `INSERT INTO pam_targets(tenant_id,target_type,id,registered_by,registered_at) VALUES($1,'ssh','owned-local-host','operator','2026-11-07T00:00:00Z')`, tenant); err != nil {
				t.Fatal(err)
			}
		}
	}, func(ctx context.Context, pool *pgxpool.Pool, _ int) {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM windows_local_account_rotations`).Scan(&count); err != nil || count != 0 {
			t.Fatal("upgrade invented native host generations", err)
		}
		for _, tenant := range []string{tenantA, tenantB} {
			if _, err := pool.Exec(ctx, `INSERT INTO windows_local_account_rotations(tenant_id,id,agent_id,account_sid,intent,prepared_event_id,prepared_at) VALUES($1,'42200000-0000-4000-8000-000000000001','42200000-0000-4000-8000-000000000002','S-1-5-21-1-2-3-1001','{}','owned-source',now())`, tenant); err != nil {
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
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM windows_local_account_rotations WHERE tenant_id=$1`, tenantB).Scan(&count); err != nil || count != 0 {
			t.Fatal("native generation metadata crossed forced RLS", err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO windows_local_account_rotations(tenant_id,id,agent_id,account_sid,intent,prepared_event_id,prepared_at) VALUES($1,'42200000-0000-4000-8000-000000000003','42200000-0000-4000-8000-000000000002','S-1-5-21-1-2-3-1001','{}','owned-source',now())`, tenantB); err == nil {
			t.Fatal("foreign native generation write bypassed forced RLS")
		}
	})
}
