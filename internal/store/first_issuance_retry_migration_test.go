// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0216PreservesOriginalOutboxAndSeparatesValidation(t *testing.T) {
	ctx := t.Context()
	prefix, expand := splitMigrationsAtVersion(t, 216)
	_, validate := splitMigrationsAtVersion(t, 217)
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
	for _, tenant := range []string{tenantA, tenantB} {
		if err := writeTenant(tenant, `INSERT INTO outbox (tenant_id,destination,payload,idempotency_key,status,attempts)
			VALUES ($1,'ca.issue',$2,'original-command','failed',10)`, tenant, []byte(`{"identity_id":"retained"}`)); err != nil {
			t.Fatal(err)
		}
	}
	applyMigrationFiles(t, ctx, pool, []migrationFile{expand})
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=ANY($1::uuid[]) AND idempotency_key='original-command'
		AND retry_attempt_limit=0 AND status='failed' AND attempts=10 AND payload=$2`, []string{tenantA, tenantB}, []byte(`{"identity_id":"retained"}`)).Scan(&count); err != nil || count != 2 {
		t.Fatalf("migration altered retained commands: %d %v", count, err)
	}
	var valid bool
	if err := pool.QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conname='outbox_retry_attempt_limit_nonnegative'`).Scan(&valid); err != nil || valid {
		t.Fatalf("constraint validated before expansion committed: %t %v", valid, err)
	}
	if err := writeTenant(tenantA, `UPDATE outbox SET retry_attempt_limit=11 WHERE tenant_id=$1 AND idempotency_key='original-command'`, tenantA); err != nil {
		t.Fatal(err)
	}
	if err := writeTenant(tenantB, `UPDATE outbox SET retry_attempt_limit=-1 WHERE tenant_id=$1 AND idempotency_key='original-command'`, tenantB); err == nil {
		t.Fatal("negative retry allowance accepted")
	}
	applyMigrationFiles(t, ctx, pool, []migrationFile{validate})
	if err := pool.QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conname='outbox_retry_attempt_limit_nonnegative'`).Scan(&valid); err != nil || !valid {
		t.Fatalf("constraint not validated: %t %v", valid, err)
	}
}
