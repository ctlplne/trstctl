// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0388KeepsSessionsDirectAndTargetsUnbound is 0388's exact
// N-1 -> N case (A254): sessions opened before the access gateway existed stay
// direct deliveries with no gateway and no ticket, registered targets stay
// unbound, and every pre-existing value is unchanged. The role checks gain the
// gateway role and still refuse an unknown one.
func TestMigration0388KeepsSessionsDirectAndTargetsUnbound(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 388)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "38800000-0000-4000-8000-000000000001"
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
			t.Fatalf("seed pre-0388 PAM rows: %v", err)
		}
	}
	seed(`INSERT INTO pam_targets (tenant_id, target_type, id, provider_id, allowed_roles, registered_by, registered_at)
		VALUES ($1, 'postgres', 'orders-db', 'orders', '{readonly}', 'op@example.test', '2026-11-04T08:00:00Z')`, tenant)
	seed(`INSERT INTO pam_targets (tenant_id, target_type, id, host, port, principals, registered_by, registered_at)
		VALUES ($1, 'ssh', 'bastion', 'bastion.internal', 22, '{deploy}', 'op@example.test', '2026-11-04T08:00:00Z')`, tenant)
	seed(`INSERT INTO pam_sessions (tenant_id, id, target_type, target_id, role, status, subject, requested_by,
		        backend_ref, started_at, expires_at)
		VALUES ($1, '38800000-0000-4000-8000-0000000000a1', 'postgres', 'orders-db', 'readonly', 'active',
		        'alice', 'alice', 'lease-0388', '2026-11-04T08:00:00Z', '2026-11-04T09:00:00Z')`, tenant)
	seed(`INSERT INTO pam_sessions (tenant_id, id, target_type, target_id, role, status, subject, requested_by,
		        backend_ref, ssh_key_id, ssh_serial, started_at, expires_at, ended_at)
		VALUES ($1, '38800000-0000-4000-8000-0000000000a2', 'ssh', 'bastion', 'deploy', 'expired',
		        'bob', 'bob', 'bastion', 'pam:38800000-0000-4000-8000-0000000000a2', 3880,
		        '2026-11-04T07:00:00Z', '2026-11-04T07:30:00Z', '2026-11-04T07:30:01Z')`, tenant)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const sessions = `SELECT (to_jsonb(o) - ARRAY['delivery','gateway_agent_id','gateway_ticket_digest'])::text FROM pam_sessions o ORDER BY id`
	const targets = `SELECT (to_jsonb(o) - ARRAY['gateway_agent_id','gateway_address'])::text FROM pam_targets o ORDER BY target_type, id`
	sessionCount, sessionSum := checksumQuery(t, ctx, pool, sessions)
	targetCount, targetSum := checksumQuery(t, ctx, pool, targets)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	if n, sum := checksumQuery(t, ctx, pool, sessions); sessionCount != 2 || n != sessionCount || sum != sessionSum {
		t.Fatalf("0388 changed session content: %d/%s before, %d/%s after", sessionCount, sessionSum, n, sum)
	}
	if n, sum := checksumQuery(t, ctx, pool, targets); targetCount != 2 || n != targetCount || sum != targetSum {
		t.Fatalf("0388 changed target content: %d/%s before, %d/%s after", targetCount, targetSum, n, sum)
	}
	var gatewaySessions, unboundTargets int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_sessions
		WHERE delivery <> 'direct' OR gateway_agent_id IS NOT NULL OR gateway_ticket_digest <> ''`).Scan(&gatewaySessions); err != nil {
		t.Fatal(err)
	}
	if gatewaySessions != 0 {
		t.Fatalf("%d pre-0388 sessions are not plain direct deliveries", gatewaySessions)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_targets
		WHERE gateway_agent_id IS NULL AND gateway_address = ''`).Scan(&unboundTargets); err != nil {
		t.Fatal(err)
	}
	if unboundTargets != 2 {
		t.Fatalf("%d of 2 pre-0388 targets are unbound", unboundTargets)
	}
	if _, err := pool.Exec(ctx, `UPDATE pam_sessions SET delivery = 'tunnel'`); err == nil {
		t.Fatal("a delivery other than direct or gateway was accepted")
	}
	for table, constraint := range map[string]string{
		"outbox":                 "outbox_required_agent_role_known",
		"agent_bootstrap_tokens": "agent_bootstrap_tokens_roles_known",
	} {
		var def string
		if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
			WHERE conrelid = $1::regclass AND conname = $2`, table, constraint).Scan(&def); err != nil {
			t.Fatalf("%s.%s: %v", table, constraint, err)
		}
		for _, role := range []string{"'host'", "'network'", "'gateway'"} {
			if !strings.Contains(def, role) {
				t.Fatalf("%s.%s = %s, missing %s", table, constraint, def, role)
			}
		}
		if strings.Contains(def, "'operator'") {
			t.Fatalf("%s.%s = %s admits an unknown role", table, constraint, def)
		}
	}
}
