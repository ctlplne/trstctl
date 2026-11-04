// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 0382 adds how a completed revocation ended an AWS STS session (N3). Leases
// from before keep every value they had, including a completed revocation, and
// none names a method: the method is recorded only by a revocation that
// completes after the migration.
func TestMigration0382KeepsLeasesWithNoRevocationMethod(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 382)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "38200000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	seed := func(statement string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, statement, args...); err != nil {
			t.Fatalf("seed a pre-0382 lease: %v", err)
		}
	}
	seed(`INSERT INTO dynamic_secret_leases
		       (tenant_id, id, tenant_epoch, idempotency_key, request_binding, provider, role,
		        backend_ref, sealed_credential, state, issue_outbox_id, revocation_status,
		        issued_at, expires_at, hard_expires_at, updated_at)
		VALUES ($1, 'lease-0382-active', 'epoch-0382', 'idem-0382-active', 'sha256:active', 'aws-sts-production',
		        'deployer', '{"role_arn":"arn:aws:iam::123456789012:role/deployer"}', 'sealed-0382'::bytea, 'active', 3820, 'none',
		        '2026-11-04T08:00:00Z', '2026-11-04T08:30:00Z', '2026-11-04T09:00:00Z', '2026-11-04T08:00:00Z')`, tenant)
	seed(`INSERT INTO dynamic_secret_leases
		       (tenant_id, id, tenant_epoch, idempotency_key, request_binding, provider, role,
		        backend_ref, sealed_credential, state, issue_outbox_id, revocation_status, revoke_outbox_id,
		        issued_at, expires_at, hard_expires_at, revoked_at, revocation_completed_at, updated_at)
		VALUES ($1, 'lease-0382-completed', 'epoch-0382', 'idem-0382-completed', 'sha256:completed', 'aws-sts-production',
		        'deployer', '{"role_arn":"arn:aws:iam::123456789012:role/deployer"}', ''::bytea, 'revoked', 3821, 'completed', 3822,
		        '2026-11-04T08:00:00Z', '2026-11-04T08:30:00Z', '2026-11-04T09:00:00Z', '2026-11-04T08:10:00Z',
		        '2026-11-04T09:00:01Z', '2026-11-04T09:00:01Z')`, tenant)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const stable = `SELECT tenant_id::text, id, tenant_epoch, idempotency_key, request_binding, provider, role,
		backend_ref, sealed_credential, credential_digest, state, issue_outbox_id, revocation_status,
		revoke_outbox_id, issued_at, expires_at, hard_expires_at, revoked_at, revocation_completed_at, updated_at
		FROM dynamic_secret_leases ORDER BY id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if beforeCount != 2 || afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0382 changed lease content: %d/%s before, %d/%s after", beforeCount, beforeChecksum, afterCount, afterChecksum)
	}
	var named int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM dynamic_secret_leases WHERE revocation_method <> ''`).Scan(&named); err != nil {
		t.Fatal(err)
	}
	if named != 0 {
		t.Fatalf("%d pre-0382 leases name a revocation method, want none", named)
	}
	if _, err := pool.Exec(ctx, `UPDATE dynamic_secret_leases SET revocation_method = 'deleted' WHERE id = 'lease-0382-completed'`); err == nil {
		t.Fatal("0382 accepted a revocation method that is neither deny_policy nor native_expiry")
	}
	if _, err := pool.Exec(ctx, `UPDATE dynamic_secret_leases SET revocation_method = 'deny_policy' WHERE id = 'lease-0382-completed'`); err != nil {
		t.Fatalf("a completed revocation could not record deny_policy: %v", err)
	}
}
