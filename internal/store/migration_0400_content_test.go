// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0400KeepsStagedAccountsUndismissed is 0400's exact N-1 -> N
// case (A260 part 2): an account staged before carries no dismissal, every
// pre-existing value is unchanged, and nothing is imported.
func TestMigration0400KeepsStagedAccountsUndismissed(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 400)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "40000000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO pam_discovered_accounts (tenant_id, provider_id, account_key, id, name, kind, privileges,
		        disabled, details, first_seen_run, first_seen_at, last_seen_run, last_seen_at, status)
		VALUES ($1, 'orders-pg', 'role:app_admin', '40000000-0000-4000-8000-0000000000a1', 'app_admin', 'database_role', '["superuser"]',
		        false, '{"can_login":"true"}', '40000000-0000-4000-8000-0000000000b1', '2026-11-05T01:00:00Z',
		        '40000000-0000-4000-8000-0000000000b1', '2026-11-05T01:00:00Z', 'staged')`, tenant); err != nil {
		t.Fatalf("seed a pre-0400 staged account: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const accounts = `SELECT (to_jsonb(o) - 'dismissed_reason' - 'dismissed_by')::text FROM pam_discovered_accounts o ORDER BY id`
	before, beforeSum := checksumQuery(t, ctx, pool, accounts)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	if after, afterSum := checksumQuery(t, ctx, pool, accounts); before != 1 || after != before || afterSum != beforeSum {
		t.Fatalf("0400 changed staged account content: %d/%s before, %d/%s after", before, beforeSum, after, afterSum)
	}
	var dismissed, imported int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_discovered_accounts WHERE dismissed_reason <> '' OR dismissed_by <> ''`).Scan(&dismissed); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pam_imported_accounts`).Scan(&imported); err != nil {
		t.Fatal(err)
	}
	if dismissed != 0 || imported != 0 {
		t.Fatalf("0400 dismissed %d and imported %d pre-0400 accounts", dismissed, imported)
	}
}
