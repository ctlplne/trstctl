// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0214PreservesCustodyAndValidatesSealedStorage(t *testing.T) {
	ctx := t.Context()
	prefix, expand := splitMigrationsAtVersion(t, 214)
	_, validate := splitMigrationsAtVersion(t, 215)
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
		if err := writeTenant(tenant, `INSERT INTO certificates (id, tenant_id, subject, sans, fingerprint, key_storage) VALUES ($1, $2, 'CN=retained', ARRAY['retained.example.test']::text[], $3, 'file')`, uuid(tenant, 214), tenant, "retained-"+string(rune('a'+index))); err != nil {
			t.Fatal(err)
		}
	}
	applyMigrationFiles(t, ctx, pool, []migrationFile{expand})
	var oldRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE key_storage = 'file' AND subject = 'CN=retained'`).Scan(&oldRows); err != nil || oldRows != 2 {
		t.Fatalf("migration changed existing custody rows: count=%d err=%v", oldRows, err)
	}
	var valid bool
	if err := pool.QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conname = 'certificates_key_storage_known'`).Scan(&valid); err != nil || valid {
		t.Fatalf("expansion scanned/validated early: %t %v", valid, err)
	}
	if err := writeTenant(tenantA, `UPDATE certificates SET key_storage = 'sealed_store' WHERE tenant_id = $1 AND id = $2`, tenantA, uuid(tenantA, 214)); err != nil {
		t.Fatal(err)
	}
	if err := writeTenant(tenantB, `UPDATE certificates SET key_storage = 'unknown-store' WHERE tenant_id = $1 AND id = $2`, tenantB, uuid(tenantB, 214)); err == nil {
		t.Fatal("expanded constraint accepts unrecognized custody")
	}
	applyMigrationFiles(t, ctx, pool, []migrationFile{validate})
	if err := pool.QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conname = 'certificates_key_storage_known'`).Scan(&valid); err != nil || !valid {
		t.Fatalf("constraint is not validated: %t %v", valid, err)
	}
}
