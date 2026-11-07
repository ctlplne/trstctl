// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"testing"
)

func TestMigration0419KeepsCustodyAndIsolatesReviewPagesA267(t *testing.T) {
	const stable = `SELECT to_jsonb(c)::text FROM secret_static_rotation_commands c ORDER BY tenant_id,id`
	tables := []string{"service_account_rotation_manifests", "service_account_rotation_manifest_pages", "service_account_rotation_manifest_hosts", "service_account_rotation_manifest_entries"}
	runPopulatedDefaultMigrationHarness(t, 419, stable, func(ctx context.Context, pool *pgxpool.Pool) {
		for _, tenant := range []string{tenantA, tenantB} {
			if _, err := pool.Exec(ctx, `INSERT INTO secret_static_rotation_commands(tenant_id,id,tenant_epoch,provider,secret_key,old_ref,phase,expected_version,result_version,sealed_old,sealed_new,sealed_preparation,provider_binding,idempotency_key_digest,request_binding,created_at,updated_at)
 VALUES($1,'41900000-0000-4000-8000-000000000001','owned-epoch','directory','service','owned-account','staged',7,8,'\x010203'::bytea,'\x040506'::bytea,'\x070809'::bytea,$2,$2,$2,'2026-11-01T00:00:00Z','2026-11-01T00:01:00Z')`, tenant, strings.Repeat("a", 64)); err != nil {
				t.Fatal(err)
			}
		}
	}, func(ctx context.Context, pool *pgxpool.Pool, want int) {
		var retained int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM secret_static_rotation_commands WHERE phase='staged' AND dependent_change_id IS NULL`).Scan(&retained); err != nil || retained != want {
			t.Fatal("upgrade changed native custody", err)
		}
		for _, table := range tables {
			var count int
			// Table names are a closed literal fixture, never a request selector.
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 0 {
				t.Fatal("upgrade invented a reviewed native effect", table, err)
			}
		}
		for _, tenant := range []string{tenantA, tenantB} {
			if _, err := pool.Exec(ctx, `INSERT INTO service_account_rotation_manifests(tenant_id,id,header,header_digest,actor,created_at,expires_at) VALUES($1,'41900000-0000-4000-8000-000000000002','{}',$2,'owned-reviewer',now(),now()+interval '15 minutes')`, tenant, strings.Repeat("b", 64)); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO service_account_rotation_manifest_pages(tenant_id,manifest_id,page_number,page,digest) VALUES($1,'41900000-0000-4000-8000-000000000002',0,'{}',$2)`, tenant, strings.Repeat("c", 64)); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO service_account_rotation_manifest_hosts(tenant_id,manifest_id,agent_id,host,digest) VALUES($1,'41900000-0000-4000-8000-000000000002','41900000-0000-4000-8000-000000000003','{}',$2)`, tenant, strings.Repeat("d", 64)); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO service_account_rotation_manifest_entries(tenant_id,manifest_id,ordinal,page_number,agent_id,ref_digest,entry) VALUES($1,'41900000-0000-4000-8000-000000000002',0,0,'41900000-0000-4000-8000-000000000003',$2,'{}')`, tenant, strings.Repeat("e", 64)); err != nil {
				t.Fatal(err)
			}
		}
		for _, table := range tables {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE trstctl_app"); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenantA); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			var count int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1", tenantB).Scan(&count); err != nil || count != 0 {
				_ = tx.Rollback(ctx)
				t.Fatal("foreign review read crossed RLS", table, err)
			}
			tag, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE tenant_id=$1", tenantB)
			if err != nil || tag.RowsAffected() != 0 {
				_ = tx.Rollback(ctx)
				t.Fatal("foreign review mutation crossed RLS", table, err)
			}
			_ = tx.Rollback(ctx)
		}
	})
}
