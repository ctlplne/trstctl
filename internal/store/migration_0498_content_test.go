// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0498PreservesStagedOutboxReceipts(t *testing.T) {
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, 498)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "49800000-0000-4000-8000-000000000001"
	if _, err := pool.Exec(ctx, `INSERT INTO outbox
		(tenant_id, destination, payload, idempotency_key, status)
		VALUES ($1, 'fixture.receipt', decode('7b7d', 'hex'), 'already-applied', 'receipt_observed')`, tenant); err != nil {
		t.Fatal(err)
	}
	const staged = `SELECT to_jsonb(r) FROM outbox r
		WHERE tenant_id = '49800000-0000-4000-8000-000000000001'`
	beforeCount, beforeDigest := checksumQuery(t, ctx, pool, staged)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if count, digest := checksumQuery(t, ctx, pool, staged); count != 1 || count != beforeCount || digest != beforeDigest {
		t.Fatal("building the receipt queue index changed the already-observed external effect")
	}
	var valid bool
	if err := pool.QueryRow(ctx, `SELECT indisvalid FROM pg_index
		WHERE indexrelid = 'outbox_observed_receipt_queue_idx'::regclass`).Scan(&valid); err != nil || !valid {
		t.Fatalf("observed receipt queue index is unavailable: %v", err)
	}
}
