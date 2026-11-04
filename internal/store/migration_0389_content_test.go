// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0389KeepsTargetsUnpinnedAndSessionsWithoutPrincipal is 0389's
// exact N-1 -> N case (A254 part 2): targets registered before it pin no host
// keys, sessions opened before it record no gateway SSH principal, and every
// pre-existing value is unchanged.
func TestMigration0389KeepsTargetsUnpinnedAndSessionsWithoutPrincipal(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 389)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "38900000-0000-4000-8000-000000000001"
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
			t.Fatalf("seed pre-0389 PAM rows: %v", err)
		}
	}
	seed(`INSERT INTO pam_targets (tenant_id, target_type, id, host, port, principals, registered_by, registered_at,
		        gateway_agent_id, gateway_address)
		VALUES ($1, 'ssh', 'bastion', 'bastion.internal', 22, '{deploy}', 'op@example.test', '2026-11-04T08:00:00Z',
		        '38900000-0000-4000-8000-0000000000b1', 'gateway.internal:8443')`, tenant)
	seed(`INSERT INTO pam_sessions (tenant_id, id, target_type, target_id, role, status, subject, requested_by,
		        backend_ref, delivery, gateway_agent_id, gateway_ticket_digest, started_at, expires_at)
		VALUES ($1, '38900000-0000-4000-8000-0000000000a1', 'postgres', 'orders-db', 'readonly', 'active',
		        'alice', 'alice', 'lease-0389', 'gateway', '38900000-0000-4000-8000-0000000000b1',
		        repeat('a', 64), '2026-11-04T08:00:00Z', '2026-11-04T09:00:00Z')`, tenant)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const sessions = `SELECT (to_jsonb(o) - 'ssh_principal')::text FROM pam_sessions o ORDER BY id`
	const targets = `SELECT (to_jsonb(o) - 'host_key_fingerprints')::text FROM pam_targets o ORDER BY target_type, id`
	sessionCount, sessionSum := checksumQuery(t, ctx, pool, sessions)
	targetCount, targetSum := checksumQuery(t, ctx, pool, targets)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	if n, sum := checksumQuery(t, ctx, pool, sessions); sessionCount != 1 || n != sessionCount || sum != sessionSum {
		t.Fatalf("0389 changed session content: %d/%s before, %d/%s after", sessionCount, sessionSum, n, sum)
	}
	if n, sum := checksumQuery(t, ctx, pool, targets); targetCount != 1 || n != targetCount || sum != targetSum {
		t.Fatalf("0389 changed target content: %d/%s before, %d/%s after", targetCount, targetSum, n, sum)
	}
	var principals, pinned int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_sessions WHERE ssh_principal <> ''`).Scan(&principals); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_targets WHERE cardinality(host_key_fingerprints) <> 0`).Scan(&pinned); err != nil {
		t.Fatal(err)
	}
	if principals != 0 || pinned != 0 {
		t.Fatalf("pre-0389 rows gained values: %d session principals, %d pinned targets", principals, pinned)
	}
}
