// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0417KeepsNativeCustodyAndIsolatesDependentRotations(t *testing.T) {
	const stable = `SELECT ((to_jsonb(c)-'dependent_change_id') || jsonb_build_object('scan',to_jsonb(s)-'observed_event_id'))::text
 FROM secret_static_rotation_commands c JOIN service_account_host_scans s USING(tenant_id)
 ORDER BY c.tenant_id,c.id,s.id`
	runPopulatedDefaultMigrationHarness(t, 417, stable, func(ctx context.Context, pool *pgxpool.Pool) {
		for _, tenant := range []string{tenantA, tenantB} {
			if _, err := pool.Exec(ctx, `INSERT INTO secret_static_rotation_commands
   (tenant_id,id,tenant_epoch,provider,secret_key,old_ref,phase,expected_version,result_version,
   sealed_old,sealed_new,sealed_preparation,provider_binding,idempotency_key_digest,request_binding,created_at,updated_at)
   VALUES($1,'41700000-0000-4000-8000-000000000001','owned-epoch','directory','service','owned-account','staged',7,8,
   '\x010203'::bytea,'\x040506'::bytea,'\x070809'::bytea,$2,$2,$2,'2026-11-01T00:00:00Z','2026-11-01T00:01:00Z')`, tenant, strings.Repeat("a", 64)); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO service_account_host_scans
   (tenant_id,id,account_id,agent_id,intent,binding_digest,status,queued_by,queued_at,queued_event_id,report,report_digest,received_at)
   VALUES($1,'41700000-0000-4000-8000-000000000002','41700000-0000-4000-8000-000000000003',
   '41700000-0000-4000-8000-000000000004','{"owned":"intent"}',$2,'complete','operator','2026-11-01T00:00:00Z',
   '41700000-0000-4000-8000-000000000005','{"owned":"signed native metadata"}',$2,'2026-11-01T00:01:00Z')`, tenant, strings.Repeat("b", 64)); err != nil {
				t.Fatal(err)
			}
		}
	}, func(ctx context.Context, pool *pgxpool.Pool, want int) {
		var legacyCommands, legacyScans, parents, steps int
		if err := pool.QueryRow(ctx, `SELECT
   (SELECT count(*) FROM secret_static_rotation_commands WHERE dependent_change_id IS NULL AND phase='staged'),
   (SELECT count(*) FROM service_account_host_scans WHERE observed_event_id IS NULL AND status='complete'),
   (SELECT count(*) FROM service_account_rotations),(SELECT count(*) FROM service_account_rotation_steps)`).Scan(&legacyCommands, &legacyScans, &parents, &steps); err != nil || legacyCommands != want || legacyScans != want || parents != 0 || steps != 0 {
			t.Fatalf("upgrade invented custody/source/effects: commands=%d scans=%d parents=%d steps=%d want=%d err=%v", legacyCommands, legacyScans, parents, steps, want, err)
		}
		for _, tenant := range []string{tenantA, tenantB} {
			if _, err := pool.Exec(ctx, `INSERT INTO service_account_rotations
    (tenant_id,id,intent,intent_digest,command_id,tenant_epoch,direction,actor,created_at,updated_at)
    VALUES($1,'41700000-0000-4000-8000-000000000003','{}',$2,'41700000-0000-4000-8000-000000000001','owned-epoch','forward','operator',now(),now())`, tenant, strings.Repeat("c", 64)); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO service_account_rotation_steps
    (tenant_id,rotation_id,step_id,intent,direction,status,queued_at)
    VALUES($1,'41700000-0000-4000-8000-000000000003',$2,'{}','forward','queued',now())`, tenant, strings.Repeat("d", 32)); err != nil {
				t.Fatal(err)
			}
		}
		var unstarted int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM service_account_rotations WHERE NOT directory_apply_started AND NOT directory_restored`).Scan(&unstarted); err != nil || unstarted != want {
			t.Fatal("new parents invented native apply/recovery", err)
		}
		for _, table := range []string{"service_account_rotations", "service_account_rotation_steps"} {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, "SET LOCAL ROLE trstctl_app"); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenantA); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			var count int
			query := `SELECT count(*) FROM service_account_rotations WHERE tenant_id=$1`
			update := `UPDATE service_account_rotations SET actor='foreign change' WHERE tenant_id=$1`
			if table == "service_account_rotation_steps" {
				query = `SELECT count(*) FROM service_account_rotation_steps WHERE tenant_id=$1`
				update = `UPDATE service_account_rotation_steps SET status='succeeded' WHERE tenant_id=$1`
			}
			if err = tx.QueryRow(ctx, query, tenantB).Scan(&count); err != nil || count != 0 {
				_ = tx.Rollback(ctx)
				t.Fatalf("%s read crossed RLS: %d %v", table, count, err)
			}
			tag, err := tx.Exec(ctx, update, tenantB)
			if err != nil || tag.RowsAffected() != 0 {
				_ = tx.Rollback(ctx)
				t.Fatalf("%s mutation crossed RLS: %v", table, err)
			}
			_ = tx.Rollback(ctx)
		}
	})
}
