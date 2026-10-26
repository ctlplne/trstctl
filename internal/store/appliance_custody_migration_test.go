// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A key an appliance generates through its management API is the appliance's:
// it was made there and it stays in the appliance's key store. The expansion
// keeps existing custody rows, accepts the new origin and storage class without
// scanning history under the table lock, still refuses unknown values, and the
// separate validation step succeeds for both constraints.
func TestMigration0315ExpandsCustodyToApplianceKeys(t *testing.T) {
	ctx := t.Context()
	prefix, expand := splitMigrationsAtVersion(t, 315)
	_, validate := splitMigrationsAtVersion(t, 316)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	writeTenant := func(tenant, statement string, args ...any) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id', $1, true)`, tenant); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, statement, args...); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	for index, tenant := range []string{tenantA, tenantB} {
		if err := writeTenant(tenant, `INSERT INTO certificates (id, tenant_id, subject, sans, fingerprint, key_origin, key_storage) VALUES ($1, $2, 'CN=retained', ARRAY['retained.example.test']::text[], $3, 'host_agent', 'kubernetes_secret')`, uuid(tenant, 315), tenant, "retained-"+string(rune('a'+index))); err != nil {
			t.Fatal(err)
		}
	}
	appliance := `UPDATE certificates SET key_origin = 'appliance', key_storage = 'appliance' WHERE tenant_id = $1 AND id = $2`
	if err := writeTenant(tenantA, appliance, tenantA, uuid(tenantA, 315)); err == nil {
		t.Fatal("the pre-expansion constraints already accept appliance custody")
	}
	applyMigrationFiles(t, ctx, pool, []migrationFile{expand})
	var oldRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE key_origin = 'host_agent' AND key_storage = 'kubernetes_secret' AND subject = 'CN=retained'`).Scan(&oldRows); err != nil || oldRows != 2 {
		t.Fatalf("migration changed existing custody rows: count=%d err=%v", oldRows, err)
	}
	for _, constraint := range []string{"certificates_key_origin_known", "certificates_key_storage_known"} {
		var valid bool
		if err := pool.QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conname = $1`, constraint).Scan(&valid); err != nil || valid {
			t.Fatalf("expansion scanned/validated %s early: %t %v", constraint, valid, err)
		}
	}
	if err := writeTenant(tenantA, appliance, tenantA, uuid(tenantA, 315)); err != nil {
		t.Fatalf("expanded constraints refuse appliance custody: %v", err)
	}
	for _, unknown := range []string{
		`UPDATE certificates SET key_origin = 'unknown-origin' WHERE tenant_id = $1 AND id = $2`,
		`UPDATE certificates SET key_storage = 'unknown-store' WHERE tenant_id = $1 AND id = $2`,
	} {
		if err := writeTenant(tenantB, unknown, tenantB, uuid(tenantB, 315)); err == nil {
			t.Fatalf("expanded constraints accept unrecognized custody: %s", unknown)
		}
	}
	applyMigrationFiles(t, ctx, pool, []migrationFile{validate})
	for _, constraint := range []string{"certificates_key_origin_known", "certificates_key_storage_known"} {
		var valid bool
		if err := pool.QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conname = $1`, constraint).Scan(&valid); err != nil || !valid {
			t.Fatalf("constraint %s is not validated: %t %v", constraint, valid, err)
		}
	}
}
