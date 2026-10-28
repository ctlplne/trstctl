// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigration0334KeepsReportRunsAndStartsUnheldAndUnexpired: 0334 adds the
// legal hold and expiry columns to compliance_report_runs. A completed run
// projected before it keeps every value and reads as not held, with no removal
// queued, not expired and no retention event; the new check refuses a negative
// sequence.
func TestMigration0334KeepsReportRunsAndStartsUnheldAndUnexpired(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 334)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "33400000-0000-4000-8000-000000000001"
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
	if err := withTenant(t, `INSERT INTO compliance_report_schedules
		(tenant_id, id, framework, name, report_type, interval_seconds, enabled, delivery, next_run_at, created_at, updated_at)
		VALUES ($1, '33400000-0000-4000-8000-0000000000b1', 'soc2', 'pack', 'framework_evidence_pack', 3600, true,
		 'audit_export', '2026-10-01T01:00:00Z', '2026-09-30T00:00:00Z', '2026-09-30T00:00:00Z')`, tenant); err != nil {
		t.Fatalf("seed a pre-0334 schedule: %v", err)
	}
	if err := withTenant(t, `INSERT INTO compliance_report_runs
		(tenant_id, id, schedule_id, due_at, framework, report_type, status, retry_generation, attempt,
		 artifact_ref, artifact_digest, completed_at, event_sequence, created_at, updated_at)
		VALUES ($1, '33400000-0000-4000-8000-0000000000a1', '33400000-0000-4000-8000-0000000000b1',
		 '2026-10-01T00:00:00Z', 'soc2', 'framework_evidence_pack', 'completed', 0, 1,
		 $2, $3, '2026-10-01T00:01:00Z', 2, '2026-10-01T00:00:00Z', '2026-10-01T00:01:00Z')`,
		tenant, "reports/"+tenant+"/33400000-0000-4000-8000-0000000000a1/a"+repeatHex64(4)+".json", "a"+repeatHex64(4)); err != nil {
		t.Fatalf("seed a pre-0334 completed run: %v", err)
	}
	const stable = `SELECT tenant_id::text, id::text, schedule_id::text, due_at, framework, report_type, status,
		retry_generation, attempt, artifact_ref, artifact_digest, completed_at, event_sequence, created_at, updated_at
		FROM compliance_report_runs ORDER BY id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if beforeCount != 1 || afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0334 changed report run content: %d/%s before, %d/%s after",
			beforeCount, beforeChecksum, afterCount, afterChecksum)
	}
	var reason, by string
	var heldNull, requestedNull, expiredNull bool
	var sequence int64
	if err := pool.QueryRow(ctx, `SELECT legal_hold_reason, legal_hold_by, legal_hold_at IS NULL,
		artifact_expiry_requested_at IS NULL, artifact_expired_at IS NULL, retention_event_sequence
		FROM compliance_report_runs`).
		Scan(&reason, &by, &heldNull, &requestedNull, &expiredNull, &sequence); err != nil {
		t.Fatal(err)
	}
	if reason != "" || by != "" || !heldNull || !requestedNull || !expiredNull || sequence != 0 {
		t.Fatalf("the run reads hold %q/%q null %v, removal queued null %v, expired null %v, sequence %d; want unheld, nothing queued, unexpired, 0",
			reason, by, heldNull, requestedNull, expiredNull, sequence)
	}
	if err := withTenant(t, `UPDATE compliance_report_runs SET retention_event_sequence = -1`); err == nil {
		t.Fatal("a negative retention_event_sequence was stored")
	}
}
