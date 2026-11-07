// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"testing"
)

func TestMigration0418PreservesClaimedCommandsAndTenantFence(t *testing.T) {
	const stable = `SELECT to_jsonb(f)::text FROM approved_target_event_fences f ORDER BY tenant_id,target_kind,command_key`
	seedKind := func(ctx context.Context, pool *pgxpool.Pool, tenant, kind, id string) {
		t.Helper()
		_, err := pool.Exec(ctx, `INSERT INTO approved_target_event_fences
 (tenant_id,target_kind,command_key,request_binding,approval_request_id,approval_intent_digest,event_id,event_type,schema_version,event_time,event_payload,payload_sha256,semantic_sha256,approval)
 VALUES($1,$2,$2,$3,$4,$5,$4,'owned.command',2,'2026-11-01T00:00:00Z','\x7b7d'::bytea,$3,$3,'{}')`, tenant, kind, strings.Repeat("a", 64), id, "sha256:"+strings.Repeat("b", 64))
		if err != nil {
			t.Fatal(err)
		}
	}
	runPopulatedDefaultMigrationHarness(t, 418, stable, func(ctx context.Context, pool *pgxpool.Pool) {
		for _, tenant := range []string{tenantA, tenantB} {
			seedKind(ctx, pool, tenant, "ephemeral_certificate", "41800000-0000-4000-8000-000000000001")
			seedKind(ctx, pool, tenant, "code_signing_command", "41800000-0000-4000-8000-000000000002")
		}
	}, func(ctx context.Context, pool *pgxpool.Pool, want int) {
		for _, tenant := range []string{tenantA, tenantB} {
			seedKind(ctx, pool, tenant, "service_reconcile_rotation", "41800000-0000-4000-8000-000000000003")
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
		var own, foreign int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM approved_target_event_fences WHERE tenant_id=$1`, tenantA).Scan(&own); err != nil || own != want/2+1 {
			t.Fatalf("new claim missing or legacy claim changed %d %v", own, err)
		}
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM approved_target_event_fences WHERE tenant_id=$1`, tenantB).Scan(&foreign); err != nil || foreign != 0 {
			t.Fatal("foreign first command leaked", err)
		}
		tag, err := tx.Exec(ctx, `DELETE FROM approved_target_event_fences WHERE tenant_id=$1`, tenantB)
		if err != nil || tag.RowsAffected() != 0 {
			t.Fatal("foreign first command deleted", err)
		}
	})
}
