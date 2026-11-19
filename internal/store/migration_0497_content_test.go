// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0497IndexesExistingDeletionReceiptsWithoutChangingThem(t *testing.T) {
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, 497)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "49700000-0000-4000-8000-000000000001"
	if _, err := pool.Exec(ctx, `INSERT INTO application_secret_mutation_receipts
		(tenant_id, event_id, semantic_sha256, request_binding, secret_name, action,
		 result_version, result_created_at, result_updated_at, applied_at)
		VALUES ($1, $2, repeat('a', 64), repeat('b', 64), 'fixture/old-name', 'delete', 0, now(), now(), now())`,
		tenant, "49700000-0000-4000-8000-000000000002"); err != nil {
		t.Fatal(err)
	}
	const retained = `SELECT to_jsonb(r) FROM application_secret_mutation_receipts r
		WHERE tenant_id = '49700000-0000-4000-8000-000000000001'`
	beforeCount, beforeDigest := checksumQuery(t, ctx, pool, retained)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if count, digest := checksumQuery(t, ctx, pool, retained); count != 1 || count != beforeCount || digest != beforeDigest {
		t.Fatal("adding the index changed a retained mutation receipt")
	}
	var valid bool
	if err := pool.QueryRow(ctx, `SELECT indisvalid FROM pg_index
		WHERE indexrelid = 'application_secret_delete_name_idx'::regclass`).Scan(&valid); err != nil || !valid {
		t.Fatalf("delete receipt lookup index is unavailable: %v", err)
	}
}
