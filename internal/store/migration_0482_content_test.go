// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// P6-L5: 0482 adds when a moved secret's history residue was last re-checked,
// and by which scan run. Moves from before it keep all their content and read
// as never re-checked.
func TestMigration0482KeepsSecretMovesUnchecked(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 482)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "48200000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO discovery_finding_secret_moves
		(tenant_id, finding_id, secret_name, secret_version, moved_by, moved_at, residue, event_sequence)
		VALUES ($1, '48200000-0000-4000-8000-0000000000f1', 'payments-slack', 1, 'operator', '2026-11-14T00:00:00Z',
		'[{"rule_id":"slack-bot-token","file":"app.env","line":2,"commit":"0123abcd"}]', 9)`, tenant); err != nil {
		t.Fatalf("seed a pre-0482 move: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const rows = `SELECT tenant_id::text, finding_id::text, secret_name, secret_version, moved_by, moved_at, residue::text,
		consumer_read_version, consumer_reader, consumer_read_at, event_sequence FROM discovery_finding_secret_moves`
	count, sum := checksumQuery(t, ctx, pool, rows)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, after := checksumQuery(t, ctx, pool, rows); count != 1 || n != count || after != sum {
		t.Fatalf("0482 changed moves: %d/%s before, %d/%s after", count, sum, n, after)
	}
	var unchecked int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM discovery_finding_secret_moves
		WHERE residue_checked_at IS NULL AND residue_run_id IS NULL`).Scan(&unchecked); err != nil || unchecked != 1 {
		t.Fatalf("pre-0482 moves read as checked: %d %v", unchecked, err)
	}
}
