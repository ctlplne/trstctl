// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0367KeepsImportBatchesAsImports: 0367 adds the operation column
// that lets a promotion or restore (A236) share the batch-import reservation. A
// batch reserved before it keeps every value and its name fence, reads as an
// import, and the new check refuses an unknown operation.
func TestMigration0367KeepsImportBatchesAsImports(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 367)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "36700000-0000-4000-8000-000000000001"
	const event = "36700000-0000-4000-8000-0000000000e1"
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
	if err := withTenant(t, `INSERT INTO application_secret_import_batches
		(tenant_id, event_id, tenant_epoch, request_binding, payload_sha256, command_payload, actor,
		 actor_subject_ref, event_time)
		VALUES ($1, $2, '36700000-0000-4000-8000-0000000000a1', $3, $4, '\x7b7d'::bytea,
		 '{"subject":"importer"}'::jsonb, 'ref-importer', '2026-11-01T00:00:00Z')`,
		tenant, event, "a"+repeatHex64(1), "b"+repeatHex64(2)); err != nil {
		t.Fatalf("seed a pre-0367 import batch: %v", err)
	}
	if err := withTenant(t, `INSERT INTO application_secret_import_name_fences (tenant_id, secret_name, event_id)
		VALUES ($1, 'app/db/password', $2)`, tenant, event); err != nil {
		t.Fatalf("seed its name fence: %v", err)
	}
	const stable = `SELECT b.tenant_id::text, b.event_id::text, b.tenant_epoch::text, b.request_binding,
		b.payload_sha256, encode(b.command_payload, 'hex'), b.actor::text, b.actor_subject_ref, b.event_time,
		f.secret_name
		FROM application_secret_import_batches b
		JOIN application_secret_import_name_fences f ON f.tenant_id = b.tenant_id AND f.event_id = b.event_id
		ORDER BY b.event_id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if beforeCount != 1 || afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0367 changed import batch content: %d/%s before, %d/%s after",
			beforeCount, beforeChecksum, afterCount, afterChecksum)
	}
	var operation string
	if err := pool.QueryRow(ctx, `SELECT operation FROM application_secret_import_batches`).Scan(&operation); err != nil {
		t.Fatal(err)
	}
	if operation != "import" {
		t.Fatalf("a pre-0367 batch reads operation %q, want import", operation)
	}
	if err := withTenant(t, `UPDATE application_secret_import_batches SET operation = 'delete'`); err == nil {
		t.Fatal("an unknown batch operation was stored")
	}
}
