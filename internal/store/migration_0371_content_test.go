// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 0371 adds the retained revocation credential (A239). Leases from before keep
// every value they had, and none carries a revocation credential: only a lease
// revoked by presenting its credential (an OAuth access token) ever gets one.
func TestMigration0371KeepsLeasesAndStartsWithNoRevocationCredential(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 371)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "37100000-0000-4000-8000-000000000001"
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
			t.Fatalf("seed a pre-0371 lease: %v", err)
		}
	}
	seed(`INSERT INTO dynamic_secret_leases
		       (tenant_id, id, tenant_epoch, idempotency_key, request_binding, provider, role,
		        backend_ref, sealed_credential, state, issue_outbox_id, revocation_status,
		        issued_at, expires_at, hard_expires_at, updated_at)
		VALUES ($1, 'lease-0371-active', 'epoch-0371', 'idem-0371-active', 'sha256:active', 'postgres-production',
		        'reader', 'trstctl_active', 'sealed-0371'::bytea, 'active', 3710, 'none',
		        '2026-11-02T12:00:00Z', '2026-11-02T12:30:00Z', '2026-11-02T13:00:00Z', '2026-11-02T12:00:00Z')`, tenant)
	seed(`INSERT INTO dynamic_secret_leases
		       (tenant_id, id, tenant_epoch, idempotency_key, request_binding, provider, role,
		        backend_ref, sealed_credential, state, issue_outbox_id, revocation_status, revoke_outbox_id,
		        issued_at, expires_at, hard_expires_at, revoked_at, updated_at)
		VALUES ($1, 'lease-0371-revoked', 'epoch-0371', 'idem-0371-revoked', 'sha256:revoked', 'postgres-production',
		        'reader', 'trstctl_revoked', ''::bytea, 'revoked', 3711, 'pending', 3712,
		        '2026-11-02T12:00:00Z', '2026-11-02T12:30:00Z', '2026-11-02T13:00:00Z', '2026-11-02T12:10:00Z',
		        '2026-11-02T12:10:00Z')`, tenant)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const stable = `SELECT tenant_id::text, id, tenant_epoch, idempotency_key, request_binding, provider, role,
		backend_ref, sealed_credential, credential_digest, state, issue_outbox_id, revocation_status,
		issued_at, expires_at, hard_expires_at, updated_at
		FROM dynamic_secret_leases ORDER BY id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if beforeCount != 2 || afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0371 changed lease content: %d/%s before, %d/%s after", beforeCount, beforeChecksum, afterCount, afterChecksum)
	}
	var withCredential int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM dynamic_secret_leases WHERE revocation_sealed_credential <> ''::bytea`).Scan(&withCredential); err != nil {
		t.Fatal(err)
	}
	if withCredential != 0 {
		t.Fatalf("%d pre-0371 leases carry a revocation credential, want none", withCredential)
	}
	// Only a revoked lease whose revocation has not completed may carry one.
	if _, err := pool.Exec(ctx, `UPDATE dynamic_secret_leases SET revocation_sealed_credential = 'x'::bytea WHERE id = 'lease-0371-active'`); err == nil {
		t.Fatal("an active lease stored a revocation credential")
	}
	if _, err := pool.Exec(ctx, `UPDATE dynamic_secret_leases SET revocation_sealed_credential = 'x'::bytea WHERE id = 'lease-0371-revoked'`); err != nil {
		t.Fatalf("a pending revocation could not keep its credential: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE dynamic_secret_leases SET revocation_status = 'completed', revocation_completed_at = now() WHERE id = 'lease-0371-revoked'`); err == nil {
		t.Fatal("a completed revocation kept its credential")
	}
}
