// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0332KeepsStaticRotationCommandsAndStartsWithNoLeaseTTL: 0332 adds
// the dynamic-lease columns to the rotation command table. A static command
// projected before it keeps every value, reads ttl_seconds 0 (no lease) and no
// new-lease expiry, and the new check refuses a negative TTL.
func TestMigration0332KeepsStaticRotationCommandsAndStartsWithNoLeaseTTL(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 332)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "33200000-0000-4000-8000-000000000001"
	withTenant := func(t *testing.T, statement string, args ...any) error {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, statement, args...); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err := withTenant(t, `INSERT INTO secret_static_rotation_commands
		(tenant_id, id, tenant_epoch, provider, provider_type, secret_key, old_ref, new_ref, phase,
		 expected_version, result_version, sealed_new, verify_mode, idempotency_key_digest, request_binding,
		 created_at, updated_at, terminal_at)
		VALUES ($1, '33200000-0000-4000-8000-0000000000c1', 'epoch-1', 'pg-main', 'postgresql', 'db/reporting',
		 'role:old', 'role:new', 'completed', 2, 3, '\x0102'::bytea, 'connected', $2, $3,
		 '2026-10-01T00:00:00Z', '2026-10-01T00:05:00Z', '2026-10-01T00:05:00Z')`,
		tenant, "a"+repeatHex64(1), "b"+repeatHex64(1)); err != nil {
		t.Fatalf("seed a pre-0332 static command: %v", err)
	}
	const stable = `SELECT tenant_id::text, id::text, tenant_epoch, provider, provider_type, secret_key, old_ref,
		new_ref, phase, expected_version, result_version, encode(sealed_new, 'hex'), verify_mode,
		idempotency_key_digest, request_binding, created_at, updated_at, terminal_at
		FROM secret_static_rotation_commands ORDER BY id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if beforeCount != 1 || afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0332 changed rotation command content: %d/%s before, %d/%s after",
			beforeCount, beforeChecksum, afterCount, afterChecksum)
	}
	var ttl int
	var expiresNull bool
	if err := pool.QueryRow(ctx, `SELECT ttl_seconds, new_expires_at IS NULL FROM secret_static_rotation_commands`).Scan(&ttl, &expiresNull); err != nil {
		t.Fatal(err)
	}
	if ttl != 0 || !expiresNull {
		t.Fatalf("the static command reads ttl_seconds %d, new_expires_at null %v; want 0 and null", ttl, expiresNull)
	}
	if err := withTenant(t, `UPDATE secret_static_rotation_commands SET ttl_seconds = -1`); err == nil {
		t.Fatal("a negative ttl_seconds was stored")
	}
}

// repeatHex64 is a 63-character hex filler; with a one-character prefix it
// makes a 64-character digest-shaped value.
func repeatHex64(n int) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 63)
	for i := range out {
		out[i] = digits[(i+n)%len(digits)]
	}
	return string(out)
}
