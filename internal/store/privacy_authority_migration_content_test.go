// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0155PreservesLegacySchedulesAndUsesUnknownEventSequence(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 155)
	if target.name != "0155_secret_rotation_schedule_commands.sql" || target.noTx {
		t.Fatalf("migration 0155 classification = name:%q no_tx:%t", target.name, target.noTx)
	}
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh 0155 content database: %v", err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	for _, row := range []struct {
		id, tenant, name string
	}{
		{"15500000-0000-4000-8000-000000000001", tenantA, "legacy-a"},
		{"15500000-0000-4000-8000-000000000002", tenantB, "legacy-b"},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO secret_rotation_schedules
			       (id, tenant_id, name, provider, secret_key, old_ref,
			        interval_seconds, enabled, next_run_at, created_at, updated_at)
			VALUES ($1, $2, $3, 'connector:ci', 'service/password', 'version:1',
			        3600, true, '2026-08-11T12:00:00Z',
			        '2026-08-11T11:00:00Z', '2026-08-11T11:30:00Z')`,
			row.id, row.tenant, row.name); err != nil {
			t.Fatalf("seed pre-0155 schedule %s: %v", row.name, err)
		}
	}
	const stableProjection = `
		SELECT id::text, tenant_id::text, name, provider, secret_key, old_ref,
		       interval_seconds::text, enabled::text, next_run_at::text,
		       COALESCE(last_run_id::text, ''), COALESCE(last_run_at::text, ''),
		       last_run_status, last_new_ref, last_error,
		       created_at::text, updated_at::text
		  FROM secret_rotation_schedules
		 ORDER BY tenant_id, id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stableProjection)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stableProjection)
	if beforeCount != 2 || afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0155 changed legacy schedule evidence: before=%d/%s after=%d/%s",
			beforeCount, beforeChecksum, afterCount, afterChecksum)
	}
	var invented int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM secret_rotation_schedules WHERE config_event_sequence <> 0`).
		Scan(&invented); err != nil {
		t.Fatalf("read 0155 legacy event-sequence defaults: %v", err)
	}
	if invented != 0 {
		t.Fatalf("0155 invented event sequence authority on %d legacy schedules", invented)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE secret_rotation_schedules SET config_event_sequence = -1`); err == nil {
		t.Fatal("0155 accepted a negative schedule event sequence")
	}
}

func TestMigration0158PreservesLegacyAuthorityAsExplicitlyUnstamped(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 158)
	if target.name != "0158_privacy_authority_stamps.sql" || target.noTx {
		t.Fatalf("migration 0158 classification = name:%q no_tx:%t", target.name, target.noTx)
	}
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh 0158 content database: %v", err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	seedMigration0158LegacyAuthority(t, ctx, pool)
	projections := map[string]string{
		"application_secret_mutation_fences": `
			SELECT tenant_id::text, secret_name, operation, event_id::text, event_type,
			       schema_version::text, approval_required::text,
			       COALESCE(encode(requester_sealed, 'hex'), ''), request_binding,
			       encode(command_payload, 'hex'), payload_sha256,
			       COALESCE(event_time::text, ''), COALESCE(approval::text, ''),
			       COALESCE(requester_ref, ''), COALESCE(actor::text, ''),
			       COALESCE(actor_subject_ref, ''), created_at::text
			  FROM application_secret_mutation_fences ORDER BY tenant_id, secret_name`,
		"approved_target_event_fences": `
			SELECT tenant_id::text, target_kind, command_key, request_binding,
			       approval_request_id::text, approval_intent_digest, event_id::text,
			       event_type, schema_version::text, event_time::text,
			       COALESCE(event_actor::text, ''), encode(event_payload, 'hex'),
			       payload_sha256, semantic_sha256, approval::text, claim_state,
			       created_at::text, updated_at::text
			  FROM approved_target_event_fences ORDER BY tenant_id, command_key`,
		"application_secret_mutation_receipts": `
			SELECT tenant_id::text, event_id::text, semantic_sha256, request_binding,
			       secret_name, action, result_version::text, result_created_at::text,
			       result_updated_at::text, applied_at::text
			  FROM application_secret_mutation_receipts ORDER BY tenant_id, event_id`,
		"code_signing_operations": `
			SELECT tenant_id::text, operation_id, idempotency_key, mode, request_hash,
			       encode(sealed_command, 'hex'), status, encode(response, 'hex'),
			       ephemeral_handle, cleanup_status, command_outbox_id::text,
			       COALESCE(cleanup_outbox_id::text, ''), last_error,
			       created_at::text, updated_at::text, COALESCE(source_event_id::text, ''),
			       COALESCE(approval_request_id::text, ''),
			       COALESCE(approval_intent_digest, ''),
			       COALESCE(command_semantic_sha256, '')
			  FROM code_signing_operations ORDER BY tenant_id, operation_id`,
	}
	type snapshot struct {
		count    int
		checksum string
	}
	before := make(map[string]snapshot, len(projections))
	for table, projection := range projections {
		count, checksum := checksumQuery(t, ctx, pool, projection)
		if count != 1 {
			t.Fatalf("precondition: %s rows=%d, want 1", table, count)
		}
		before[table] = snapshot{count: count, checksum: checksum}
	}

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	for table, projection := range projections {
		count, checksum := checksumQuery(t, ctx, pool, projection)
		if count != before[table].count || checksum != before[table].checksum {
			t.Errorf("0158 changed legacy %s evidence: before=%d/%s after=%d/%s",
				table, before[table].count, before[table].checksum, count, checksum)
		}
	}

	assertMigration0158LegacyDefaults(t, ctx, pool)
}

func seedMigration0158LegacyAuthority(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	digest := strings.Repeat("a", 64)
	binding := strings.Repeat("b", 64)
	if _, err := pool.Exec(ctx, `
		INSERT INTO application_secret_mutation_fences
		       (tenant_id, secret_name, operation, event_id, event_type,
		        schema_version, approval_required, request_binding,
		        command_payload, payload_sha256, event_time, created_at)
		VALUES ($1, 'migration/secret', 'rotate',
		        '15800000-0000-4000-8000-000000000001', 'secret.rotated',
		        1, false, $2, $3, $4,
		        '2026-08-11T12:00:00Z', '2026-08-11T12:00:01Z')`,
		tenantA, binding, []byte("sealed-command"), digest); err != nil {
		t.Fatalf("seed pre-0158 application-secret fence: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO application_secret_mutation_receipts
		       (tenant_id, event_id, semantic_sha256, request_binding, secret_name,
		        action, result_version, result_created_at, result_updated_at, applied_at)
		VALUES ($1, '15800000-0000-4000-8000-000000000002', $2, $3,
		        'migration/secret', 'rotate', 2,
		        '2026-08-11T12:00:00Z', '2026-08-11T12:00:01Z',
		        '2026-08-11T12:00:02Z')`, tenantA, digest, binding); err != nil {
		t.Fatalf("seed pre-0158 application-secret receipt: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO approved_target_event_fences
		       (tenant_id, target_kind, command_key, request_binding,
		        approval_request_id, approval_intent_digest, event_id, event_type,
		        schema_version, event_time, event_payload, payload_sha256,
		        semantic_sha256, approval, created_at, updated_at)
		VALUES ($1, 'code_signing_command', 'migration-code-sign', $2,
		        '15800000-0000-4000-8000-000000000003', $3,
		        '15800000-0000-4000-8000-000000000004', 'codesign.commanded',
		        1, '2026-08-11T12:00:00Z', $4, $5, $5,
		        '{"request_id":"15800000-0000-4000-8000-000000000003"}'::jsonb,
		        '2026-08-11T12:00:01Z', '2026-08-11T12:00:01Z')`,
		tenantB, binding, "sha256:"+digest, []byte("event-payload"), digest); err != nil {
		t.Fatalf("seed pre-0158 approved target fence: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO code_signing_operations
		       (tenant_id, operation_id, idempotency_key, mode, request_hash,
		        sealed_command, status, command_outbox_id, created_at, updated_at)
		VALUES ($1, 'migration-code-sign', 'migration-code-sign-key', 'key', $2,
		        $3, 'queued', 158, '2026-08-11T12:00:00Z', '2026-08-11T12:00:01Z')`,
		tenantB, digest, []byte("sealed-code-signing-command")); err != nil {
		t.Fatalf("seed pre-0158 code-signing operation: %v", err)
	}
}

func assertMigration0158LegacyDefaults(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	var bad int
	checks := []struct {
		name, query string
	}{
		{"application secret fence", `SELECT count(*) FROM application_secret_mutation_fences
			WHERE privacy_rewrite_version <> 0 OR privacy_subject_ref IS NOT NULL
			   OR privacy_erasure_operation_id IS NOT NULL OR privacy_erasure_event_id IS NOT NULL
			   OR privacy_disposition <> 'none'`},
		{"approved target fence", `SELECT count(*) FROM approved_target_event_fences
			WHERE semantic_version <> 1 OR privacy_rewrite_version <> 0
			   OR privacy_subject_ref IS NOT NULL OR privacy_erasure_operation_id IS NOT NULL
			   OR privacy_erasure_event_id IS NOT NULL OR privacy_disposition <> 'none'`},
		{"application secret receipt", `SELECT count(*) FROM application_secret_mutation_receipts
			WHERE semantic_version <> 1`},
		{"code signing operation", `SELECT count(*) FROM code_signing_operations
			WHERE approval_authority_version <> 0 OR approval_resource_kind IS NOT NULL
			   OR approval_resource_id IS NOT NULL OR approval_action IS NOT NULL
			   OR approval_target_version IS NOT NULL OR privacy_rewrite_version <> 0
			   OR privacy_subject_ref IS NOT NULL OR privacy_erasure_operation_id IS NOT NULL
			   OR privacy_erasure_event_id IS NOT NULL OR privacy_disposition <> 'none'`},
	}
	for _, check := range checks {
		if err := pool.QueryRow(ctx, check.query).Scan(&bad); err != nil {
			t.Fatalf("read 0158 %s defaults: %v", check.name, err)
		}
		if bad != 0 {
			t.Errorf("0158 fabricated privacy or semantic authority on %d legacy %s rows", bad, check.name)
		}
	}
}
