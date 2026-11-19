// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0494KeepsLegacyRollbackPublicationUnknown(t *testing.T) {
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, 494)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	applyMigrationFiles(t, ctx, pool, prefix)
	const tenant = "49400000-0000-4000-8000-000000000001"
	const oldFence = "49400000-0000-4000-8000-000000000002"
	const newFence = "49400000-0000-4000-8000-000000000003"
	seed := func(name, eventID string) {
		t.Helper()
		_, err := pool.Exec(ctx, `INSERT INTO application_secret_mutation_fences
			(tenant_id, secret_name, event_id, operation, event_type, schema_version,
			 approval_required, request_binding, command_payload, payload_sha256, event_time)
			VALUES ($1, $2, $3, 'rotate', 'application_secret.rotated', 1, false,
			        repeat('a',64), 'fixture-payload'::bytea, repeat('b',64), now())`, tenant, name, eventID)
		if err != nil {
			t.Fatal(err)
		}
	}
	seed("legacy/fence", oldFence)
	const retained = `SELECT to_jsonb(f) - 'rollback_publication_authorized' FROM application_secret_mutation_fences f
		WHERE tenant_id = '49400000-0000-4000-8000-000000000001' AND event_id = '49400000-0000-4000-8000-000000000002'`
	beforeCount, beforeDigest := checksumQuery(t, ctx, pool, retained)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if count, digest := checksumQuery(t, ctx, pool, retained); count != 1 || count != beforeCount || digest != beforeDigest {
		t.Fatal("migration changed the retained reservation")
	}
	seed("legacy-writer/fence", newFence)
	var legacyUnknown, legacyWriterUnknown bool
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT rollback_publication_authorized IS NULL FROM application_secret_mutation_fences WHERE tenant_id = $1 AND event_id = $2),
		(SELECT rollback_publication_authorized IS NULL FROM application_secret_mutation_fences WHERE tenant_id = $1 AND event_id = $3)`,
		tenant, oldFence, newFence).Scan(&legacyUnknown, &legacyWriterUnknown); err != nil || !legacyUnknown || !legacyWriterUnknown {
		t.Fatalf("legacy reservations and legacy-writer drafts must retain unknown authority: %v", err)
	}
}
