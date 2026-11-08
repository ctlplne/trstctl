// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// X5: 0435 adds the session-observer role to the closed set a bootstrap token may
// grant. Tokens from before it keep their grants; an unknown role is still
// refused.
func TestMigration0435KeepsTokensAndAdmitsTheSessionObserverRole(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 435)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "43500000-0000-4000-8000-000000000001"
	exec := func(sql string, args ...any) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	insert := func(id, hash, roles string) error {
		return exec(`INSERT INTO agent_bootstrap_tokens (id, tenant_id, token_hash, expires_at, granted_roles)
			VALUES ($1, $2, $3, now() + interval '1 hour', $4::text[])`, id, tenant, hash, roles)
	}
	if err := insert("43500000-0000-4000-8000-0000000000a1", "x5-hash-a1", "{host,network,observer,gateway}"); err != nil {
		t.Fatalf("seed a pre-0435 token: %v", err)
	}
	if err := insert("43500000-0000-4000-8000-0000000000a2", "x5-hash-a2", "{session-observer}"); err == nil {
		t.Fatal("before 0435 a token granted the session-observer role")
	}
	const tokens = `SELECT id::text, token_hash, granted_roles, expires_at FROM agent_bootstrap_tokens ORDER BY id` // #nosec G101 -- a query naming the hash column; no credential value (CWE-798)
	count, sum := checksumQuery(t, ctx, pool, tokens)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, after := checksumQuery(t, ctx, pool, tokens); count != 1 || n != count || after != sum {
		t.Fatalf("0435 changed tokens: %d/%s before, %d/%s after", count, sum, n, after)
	}
	if err := insert("43500000-0000-4000-8000-0000000000a3", "x5-hash-a3", "{host,observer,gateway,session-observer}"); err != nil {
		t.Fatalf("0435 refused the session-observer role: %v", err)
	}
	if err := insert("43500000-0000-4000-8000-0000000000a4", "x5-hash-a4", "{sniffer}"); err == nil {
		t.Fatal("0435 accepted a role trstctl does not grant")
	}
}
