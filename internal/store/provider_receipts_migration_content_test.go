// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0224PreservesAuthorityWithoutInventingCompletion(t *testing.T) {
	for _, fixture := range []struct {
		name, seed, snapshot string
	}{
		{name: "empty"},
		{"customer", `INSERT INTO provider_tenants VALUES ($1,'legacy','Legacy','suspended',now(),now())`,
			`SELECT to_jsonb(t)::text FROM provider_tenants t ORDER BY tenant_id`},
		{"operator", `INSERT INTO provider_operators (id,external_id,user_name,role,active,source,created_at,updated_at,deprovisioned_at)
		 VALUES ('leaver','external','worker','operator',false,'scim:test',now(),now(),now())`,
			`SELECT to_jsonb(t)::text FROM provider_operators t ORDER BY tenant_id,id`},
		{"delegation", `INSERT INTO provider_operator_delegations (operator_id,customer_tenant_id,operation,revoked_at,revoked_by)
		 VALUES ('leaver',$1,'read',now(),'admin')`,
			`SELECT to_jsonb(t)::text FROM provider_operator_delegations t ORDER BY tenant_id,operator_id,customer_tenant_id,operation`},
		{"emergency", `INSERT INTO provider_breakglass_grants (id,tenant_id,operator_id,requested_at,expires_at,revoked_at)
		 VALUES ('closed',$1,'worker',now(),now(),now())`,
			`SELECT to_jsonb(t)::text FROM provider_breakglass_grants t ORDER BY tenant_id,id`},
		{"quota", `INSERT INTO provider_tenant_quotas (tenant_id,max_certificates_stored) VALUES ($1,0)`,
			`SELECT to_jsonb(t)::text FROM provider_tenant_quotas t ORDER BY tenant_id`},
		{"brand", `INSERT INTO tenant_branding (tenant_id,product_name) VALUES ($1,'Legacy brand')`,
			`SELECT to_jsonb(t)::text FROM tenant_branding t ORDER BY tenant_id`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			ctx := t.Context()
			prefix, target := splitMigrationsAtVersion(t, 224)
			pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			applyMigrationFiles(t, ctx, pool, prefix)
			var beforeCount int
			var beforeChecksum string
			if fixture.seed != "" {
				var args []any
				if strings.Contains(fixture.seed, "$1") {
					args = []any{tenantA}
				}
				if _, err := pool.Exec(ctx, fixture.seed, args...); err != nil {
					t.Fatal(err)
				}
				beforeCount, beforeChecksum = checksumQuery(t, ctx, pool, fixture.snapshot)
				if beforeCount != 1 {
					t.Fatalf("legacy fixture has %d rows", beforeCount)
				}
			}
			applyMigrationFiles(t, ctx, pool, []migrationFile{target})
			if fixture.seed != "" {
				count, checksum := checksumQuery(t, ctx, pool, fixture.snapshot)
				if count != beforeCount || checksum != beforeChecksum {
					t.Fatal("migration changed legacy authority")
				}
			}
			var needsRebuild bool
			if err := pool.QueryRow(ctx, `SELECT needs_rebuild FROM provider_authority_projection_state
			 WHERE tenant_id='00000000-0000-0000-0000-000000000000'`).Scan(&needsRebuild); err != nil || needsRebuild != (fixture.seed != "") {
				t.Fatalf("upgrade uncertainty=%v err=%v", needsRebuild, err)
			}
			var receipts int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM provider_authority_projection_receipts`).Scan(&receipts); err != nil || receipts != 0 {
				t.Fatalf("migration fabricated completed events: %d, %v", receipts, err)
			}
			for _, table := range []string{"provider_authority_projection_state", "provider_authority_projection_receipts"} {
				var enabled, forced bool
				if err := pool.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&enabled, &forced); err != nil || !enabled || !forced {
					t.Fatalf("%s lacks forced RLS: %v/%v %v", table, enabled, forced, err)
				}
			}
			if _, err := pool.Exec(ctx, `INSERT INTO provider_authority_projection_receipts VALUES
			 ('00000000-0000-0000-0000-000000000000',1,'authority-event',$1)`, strings.Repeat("a", 64)); err != nil {
				t.Fatal(err)
			}
			for _, tenant := range []string{tenantA, tenantB} {
				tx, err := pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				if _, err := tx.Exec(ctx, `SET LOCAL ROLE trstctl_app`); err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
					t.Fatal(err)
				}
				var visible int
				if err := tx.QueryRow(ctx, `SELECT
				 (SELECT count(*) FROM provider_authority_projection_receipts) +
				 (SELECT count(*) FROM provider_authority_projection_state)`).Scan(&visible); err != nil || visible != 0 {
					t.Fatalf("customer can see Provider completion authority: %d, %v", visible, err)
				}
				if tag, err := tx.Exec(ctx, `UPDATE provider_authority_projection_state SET needs_rebuild=false
				 WHERE tenant_id='00000000-0000-0000-0000-000000000000'`); err != nil || tag.RowsAffected() != 0 {
					t.Fatalf("customer altered Provider upgrade authority: %v, %v", tag, err)
				}
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
