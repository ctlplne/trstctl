// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0159RetainsNMinusOneEvidenceAndAdmitsOneCurrentLifecycleNamespace(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 159)
	if target.name != "0159_secret_rotation_schedule_registration_identity.sql" || target.noTx {
		t.Fatalf("migration 0159 classification = name:%q no_tx:%t", target.name, target.noTx)
	}
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh 0159 content database: %v", err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const (
		legacyKey       = "migration-0159-v2-tick"
		legacyBinding   = "migration-0159-v2-binding"
		legacyRunID     = "15900000-0000-4000-8000-000000000001"
		currentKey      = "migration-0159-v3-tick"
		currentBinding  = "migration-0159-v3-binding"
		currentRunID    = "15900000-0000-4000-8000-000000000002"
		forkedRunID     = "15900000-0000-4000-8000-000000000003"
		scheduleID      = "15900000-0000-4000-8000-000000000106"
		registrationID  = "legacy-registration-id-without-modern-prefix"
		registrationSeq = int64(9)
	)
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (tenant_id, name, event_seq) VALUES ($1, 'migration-0159', $2)`,
		tenantA, registrationSeq); err != nil {
		t.Fatalf("seed migration tenant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO idempotency_keys (tenant_id, key, status, request_binding, created_at)
		 VALUES ($1, $2, 'bound', $3, '2026-08-11T12:00:00Z')`,
		tenantA, legacyKey, legacyBinding); err != nil {
		t.Fatalf("seed v2 outer authority: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO secret_rotation_schedule_scan_cursors
		        (tenant_id, active_tick_key, active_tick_binding, lease_token,
		         lease_until, lease_generation, generation)
		 VALUES ($1, $2, $3, 'legacy-owner', '2099-01-01T00:00:00Z', 1, 0)`,
		tenantA, legacyKey, legacyBinding); err != nil {
		t.Fatalf("seed v2 active cursor: %v", err)
	}
	initialReceipt := `{"ran":0,"scanned":0,"runs":[],"deferred":[],"run_limit_reached":false,"scan_limit_reached":false,"complete":false,"partial":false}`
	if _, err := pool.Exec(ctx,
		`INSERT INTO secret_rotation_schedule_ticks
		        (tenant_id, idempotency_key, request_binding, due_through,
		         start_schedule_id, after_schedule_id, snapshot_count, receipt,
		         owner_token, owner_generation, created_at, updated_at)
		 VALUES ($1, $2, $3, '2026-08-11T12:00:00Z',
		         '00000000-0000-0000-0000-000000000000',
		         '00000000-0000-0000-0000-000000000000', 1, $4::jsonb,
		         'legacy-owner', 1, '2026-08-11T12:00:00Z', '2026-08-11T12:00:00Z')`,
		tenantA, legacyKey, legacyBinding, initialReceipt); err != nil {
		t.Fatalf("seed v2 tick: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO secret_rotation_schedule_tick_rows
		        (tenant_id, idempotency_key, ordinal, schedule_id, due_at,
		         provider, secret_key, old_ref, interval_seconds, config_event_sequence)
		 VALUES ($1, $2, 1, $3, '2026-08-11T11:59:00Z',
		         'connector:ci', 'rotation/migration', 'version:1', 60, 1)`,
		tenantA, legacyKey, scheduleID); err != nil {
		t.Fatalf("seed v2 tick row: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO secret_rotation_schedule_commands
		        (tenant_id, schedule_id, run_id, due_at, provider, secret_key,
		         old_ref, interval_seconds, config_event_sequence,
		         tick_idempotency_key, tick_ordinal,
		         command_key, request_binding, terminal_event_id,
		         created_at, updated_at)
		 VALUES ($1, $2, $3, '2026-08-11T11:59:00Z', 'connector:ci',
		         'rotation/migration', 'version:1', 60, 1, $4, 1,
		         'legacy-command', 'legacy-command-binding', 'legacy-terminal-event',
		         '2026-08-11T12:00:00Z', '2026-08-11T12:00:00Z')`,
		tenantA, scheduleID, legacyRunID, legacyKey); err != nil {
		t.Fatalf("seed v2 command: %v", err)
	}

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	var tickVersion, rowVersion, commandVersion int
	var tickRegistrationID string
	var tickRegistrationSeq int64
	if err := pool.QueryRow(ctx,
		`SELECT t.identity_version, t.tenant_registration_event_id,
		        t.tenant_registration_event_sequence, r.identity_version, c.identity_version
		   FROM secret_rotation_schedule_ticks t
		   JOIN secret_rotation_schedule_tick_rows r
		     ON r.tenant_id = t.tenant_id AND r.idempotency_key = t.idempotency_key
		   JOIN secret_rotation_schedule_commands c ON c.tenant_id = t.tenant_id
		  WHERE t.tenant_id = $1 AND t.idempotency_key = $2`, tenantA, legacyKey).
		Scan(&tickVersion, &tickRegistrationID, &tickRegistrationSeq, &rowVersion, &commandVersion); err != nil {
		t.Fatalf("load retained v2 evidence: %v", err)
	}
	if tickVersion != 2 || rowVersion != 2 || commandVersion != 2 ||
		tickRegistrationID != "" || tickRegistrationSeq != 0 {
		t.Fatalf("migration invented v2 registration authority: tick=%d/%q/%d row=%d command=%d",
			tickVersion, tickRegistrationID, tickRegistrationSeq, rowVersion, commandVersion)
	}
	var activeKey, leaseToken string
	if err := pool.QueryRow(ctx,
		`SELECT active_tick_key, lease_token
		   FROM secret_rotation_schedule_scan_cursors WHERE tenant_id = $1`, tenantA).
		Scan(&activeKey, &leaseToken); err != nil {
		t.Fatalf("load migrated cursor: %v", err)
	}
	if activeKey != "" || leaseToken != "" {
		t.Fatalf("migration left N-1 cursor live: key=%q token=%q", activeKey, leaseToken)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO idempotency_keys (tenant_id, key, status, request_binding, created_at)
		 VALUES ($1, $2, 'bound', $3, '2026-08-11T12:00:01Z')`,
		tenantA, currentKey, currentBinding); err != nil {
		t.Fatalf("seed v3 outer authority: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO secret_rotation_schedule_ticks
		        (tenant_id, identity_version, tenant_registration_event_id,
		         tenant_registration_event_sequence,
		         idempotency_key, request_binding, due_through,
		         start_schedule_id, after_schedule_id, snapshot_count, receipt,
		         owner_token, owner_generation, created_at, updated_at)
		 VALUES ($1, 3, $2, $3, $4, $5, '2026-08-11T12:00:01Z',
		         '00000000-0000-0000-0000-000000000000',
		         '00000000-0000-0000-0000-000000000000', 1, $6::jsonb,
		         'current-owner', 1, '2026-08-11T12:00:01Z', '2026-08-11T12:00:01Z')`,
		tenantA, registrationID, registrationSeq, currentKey, currentBinding, initialReceipt); err != nil {
		t.Fatalf("insert current lifecycle tick with legacy-shaped event ID: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO secret_rotation_schedule_tick_rows
		        (tenant_id, identity_version, tenant_registration_event_id,
		         tenant_registration_event_sequence,
		         idempotency_key, ordinal, schedule_id, due_at,
		         provider, secret_key, old_ref, interval_seconds, config_event_sequence)
		 VALUES ($1, 3, $2, $3, $4, 1, $5, '2026-08-11T11:59:00Z',
		         'connector:ci', 'rotation/migration', 'version:1', 60, 10)`,
		tenantA, registrationID, registrationSeq, currentKey, scheduleID); err != nil {
		t.Fatalf("insert current lifecycle tick row: %v", err)
	}
	insertCurrentCommand := func(runID, eventID string) error {
		_, err := pool.Exec(ctx,
			`INSERT INTO secret_rotation_schedule_commands
			        (tenant_id, identity_version, tenant_registration_event_id,
			         tenant_registration_event_sequence,
			         schedule_id, run_id, due_at, provider, secret_key,
			         old_ref, interval_seconds, config_event_sequence,
			         tick_idempotency_key, tick_ordinal,
			         command_key, request_binding, terminal_event_id,
			         created_at, updated_at)
			 VALUES ($1, 3, $2, $3, $4, $5, '2026-08-11T11:59:00Z',
			         'connector:ci', 'rotation/migration', 'version:1', 60, 10,
			         $6, 1, $7, $8, $9,
			         '2026-08-11T12:00:01Z', '2026-08-11T12:00:01Z')`,
			tenantA, eventID, registrationSeq, scheduleID, runID, currentKey,
			"command-"+runID, "binding-"+runID, "terminal-"+runID)
		return err
	}
	if err := insertCurrentCommand(currentRunID, registrationID); err != nil {
		t.Fatalf("v2 history blocked current lifecycle command: %v", err)
	}
	if err := insertCurrentCommand(forkedRunID, "wrong-event-id-same-sequence"); err == nil {
		t.Fatal("same verified registration sequence admitted a second due-edge namespace")
	}
	var v2Commands, v3Commands int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE identity_version = 2),
		        count(*) FILTER (WHERE identity_version = 3)
		   FROM secret_rotation_schedule_commands
		  WHERE tenant_id = $1 AND schedule_id = $2`, tenantA, scheduleID).
		Scan(&v2Commands, &v3Commands); err != nil {
		t.Fatalf("count migration command generations: %v", err)
	}
	if v2Commands != 1 || v3Commands != 1 {
		t.Fatalf("migration command generations = v2:%d v3:%d, want one retained and one current",
			v2Commands, v3Commands)
	}
}
