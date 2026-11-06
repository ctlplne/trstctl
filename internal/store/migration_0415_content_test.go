// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
)

func TestMigration0415PreservesRegistrationsAndIsolatesHostInventory(t *testing.T) {
	const stable = `SELECT to_jsonb(t)::text FROM pam_targets t ORDER BY tenant_id,target_type,id`
	runPopulatedDefaultMigrationHarness(t, 415, stable, func(ctx context.Context, pool *pgxpool.Pool) {
		for _, tenant := range []string{tenantA, tenantB} {
			if _, err := pool.Exec(ctx, `INSERT INTO pam_targets(tenant_id,target_type,id,registered_by,registered_at) VALUES($1,'ssh','owned-service','operator','2026-11-06T00:00:00Z')`, tenant); err != nil {
				t.Fatal(err)
			}
		}
	}, func(ctx context.Context, pool *pgxpool.Pool, _ int) {
		var hosts, scans int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM service_account_hosts),(SELECT count(*) FROM service_account_host_scans)`).Scan(&hosts, &scans); err != nil || hosts != 0 || scans != 0 {
			t.Fatal("upgrade invented a native host binding or inventory", err)
		}
		for _, tenant := range []string{tenantA, tenantB} {
			if _, err := pool.Exec(ctx, `INSERT INTO service_account_hosts(tenant_id,account_id,agent_id,binding,revision,enabled,saved_by,updated_at) VALUES($1,'41500000-0000-4000-8000-000000000001','41500000-0000-4000-8000-000000000002','{}',1,true,'operator',now())`, tenant); err != nil {
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
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM service_account_hosts WHERE tenant_id=$1`, tenantB).Scan(&hosts); err != nil || hosts != 0 {
			t.Fatal("host binding crossed forced RLS", err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO service_account_hosts(tenant_id,account_id,agent_id,binding,revision,enabled,saved_by,updated_at) VALUES($1,'41500000-0000-4000-8000-000000000003','41500000-0000-4000-8000-000000000002','{}',1,true,'operator',now())`, tenantB); err == nil {
			t.Fatal("foreign host insertion bypassed forced RLS")
		}
	})
}
