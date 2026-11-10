// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 0437 adds who requested a dynamic-secret lease (G1-L1). Leases from before
// keep every value they had and name no requester: the event log holds their
// requester only in a non-reversible request binding.
func TestMigration0437KeepsLeasesWithNoRequester(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 437)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "43700000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO dynamic_secret_leases
		       (tenant_id, id, tenant_epoch, idempotency_key, request_binding, provider, role,
		        backend_ref, sealed_credential, state, issue_outbox_id, revocation_status,
		        issued_at, expires_at, hard_expires_at, updated_at)
		VALUES ($1, 'lease-0437-active', 'epoch-0437', 'idem-0437', 'sha256:active', 'warehouse-pg',
		        'readonly', 'trstctl_readonly_0437', 'sealed-0437'::bytea, 'active', 4370, 'none',
		        '2026-11-10T08:00:00Z', '2026-11-10T08:30:00Z', '2026-11-10T09:00:00Z', '2026-11-10T08:00:00Z')`, tenant); err != nil {
		t.Fatalf("seed a pre-0437 lease: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const stable = `SELECT tenant_id::text, id, tenant_epoch, idempotency_key, request_binding, provider, role,
		backend_ref, sealed_credential, credential_digest, state, issue_outbox_id, revocation_status,
		issued_at, expires_at, hard_expires_at, revocation_method, updated_at
		FROM dynamic_secret_leases ORDER BY id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if beforeCount != 1 || afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0437 changed lease content: %d/%s before, %d/%s after", beforeCount, beforeChecksum, afterCount, afterChecksum)
	}
	var named int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM dynamic_secret_leases WHERE requested_by <> ''`).Scan(&named); err != nil {
		t.Fatal(err)
	}
	if named != 0 {
		t.Fatalf("%d pre-0437 leases name a requester, want none", named)
	}
}
