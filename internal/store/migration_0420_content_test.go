// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"testing"
)

func TestMigration0420PreservesLegacyNativeProgressA267(t *testing.T) {
	const stable = `SELECT (to_jsonb(r)-'manifest_cursor'-'manifest_cursor_source_id'-'manifest_cursor_sequence')::text FROM service_account_rotations r ORDER BY tenant_id,id`
	runPopulatedDefaultMigrationHarness(t, 420, stable, func(ctx context.Context, pool *pgxpool.Pool) {
		for _, tenant := range []string{tenantA, tenantB} {
			if _, err := pool.Exec(ctx, `INSERT INTO service_account_rotations(tenant_id,id,intent,intent_digest,command_id,tenant_epoch,direction,actor,created_at,updated_at) VALUES($1,'42000000-0000-4000-8000-000000000001','{}',$2,'42000000-0000-4000-8000-000000000002','owned-epoch','inverse','owned-operator',now(),now())`, tenant, strings.Repeat("a", 64)); err != nil {
				t.Fatal(err)
			}
		}
	}, func(ctx context.Context, pool *pgxpool.Pool, want int) {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM service_account_rotations WHERE manifest_cursor IS NULL AND manifest_cursor_source_id='' AND manifest_cursor_sequence=0 AND direction='inverse'`).Scan(&count); err != nil || count != want {
			t.Fatal("upgrade invented or rewound native progress", err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE trstctl_app"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenantA); err != nil {
			t.Fatal(err)
		}
		tag, err := tx.Exec(ctx, `UPDATE service_account_rotations SET manifest_cursor_sequence=999 WHERE tenant_id=$1`, tenantB)
		if err != nil || tag.RowsAffected() != 0 {
			t.Fatal("foreign cursor crossed RLS", err)
		}
	})
}
