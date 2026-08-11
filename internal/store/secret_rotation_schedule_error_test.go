// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/store"
)

func TestCanonicalSecretRotationScheduleErrorRejectsHistoricalProviderText(t *testing.T) {
	const sensitive = "credential=super-secret subject=alice@example.test remote=vault/alice"
	for _, tc := range []struct {
		status string
		want   string
	}{
		{status: "failed", want: "scheduled rotation failed"},
		{status: "delivery_failed", want: "connector delivery failed"},
		{status: "rollback_failed", want: "scheduled rotation rollback failed"},
		{status: "unsupported", want: "scheduled rotation is unavailable"},
		{status: "completed", want: ""},
	} {
		got := store.CanonicalSecretRotationScheduleError(tc.status, sensitive)
		if got != tc.want || strings.Contains(got, sensitive) || strings.Contains(got, "alice") {
			t.Fatalf("status %q canonical detail = %q, want %q", tc.status, got, tc.want)
		}
	}
	if got := store.CanonicalSecretRotationScheduleError("failed", "no such secret"); got != "no such secret" {
		t.Fatalf("known scheduler detail = %q", got)
	}
}

func TestLegacySecretRotationScheduleEventReplayProjectsClosedError(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	dueAt := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	const (
		scheduleID = "16100000-0000-4000-8000-000000000001"
		sensitive  = "credential=super-secret subject=alice@example.test remote=vault/alice"
	)
	seedSecretRotationSchedule(t, s, store.SecretRotationSchedule{
		ID: scheduleID, TenantID: tenantA, Name: "legacy-error-replay",
		Provider: "connector:legacy", Key: "rotation/legacy", OldRef: "version:1",
		IntervalSeconds: 60, Enabled: true, NextRunAt: dueAt,
	})
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretRotationScheduleRunTx(ctx, tx, store.SecretRotationScheduleRun{
			TenantID: tenantA, ScheduleID: scheduleID,
			RunID:         "16100000-0000-4000-8000-000000000002",
			SchemaVersion: 1, Status: "delivery_failed", NewRef: "version:2",
			Error: sensitive, RanAt: dueAt.Add(time.Minute), EventSequence: 3,
		})
	}); err != nil {
		t.Fatalf("replay legacy scheduler event: %v", err)
	}
	var stored string
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT last_error FROM secret_rotation_schedules
			  WHERE tenant_id = $1 AND id = $2`, tenantA, scheduleID).Scan(&stored)
	}); err != nil {
		t.Fatalf("read replayed scheduler row: %v", err)
	}
	if stored != "connector delivery failed" || strings.Contains(stored, sensitive) {
		t.Fatalf("legacy event replay persisted %q", stored)
	}
}

func TestMigration0161ScrubsHistoricalScheduleErrorsAndRejectsNewRawText(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 161)
	if target.name != "0161_secret_rotation_schedule_error_vocabulary.sql" || target.noTx {
		t.Fatalf("migration 0161 classification = name:%q no_tx:%t", target.name, target.noTx)
	}
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh 0161 content database: %v", err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const sensitive = "credential=super-secret subject=alice@example.test remote=vault/alice"
	for index, status := range []string{"failed", "delivery_failed"} {
		id := []string{
			"16100000-0000-4000-8000-000000000011",
			"16100000-0000-4000-8000-000000000012",
		}[index]
		if _, err := pool.Exec(ctx,
			`INSERT INTO secret_rotation_schedules
			        (id, tenant_id, name, provider, secret_key, old_ref,
			         interval_seconds, enabled, next_run_at, last_run_status,
			         last_error, created_at, updated_at)
			 VALUES ($1, $2, $3, 'connector:legacy', 'rotation/legacy', 'version:1',
			         60, true, '2026-08-11T12:00:00Z', $4, $5,
			         '2026-08-11T11:00:00Z', '2026-08-11T11:00:00Z')`,
			id, tenantA, "migration-error-"+status, status, sensitive); err != nil {
			t.Fatalf("seed pre-0161 %s row: %v", status, err)
		}
	}

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	rows, err := pool.Query(ctx,
		`SELECT last_run_status, last_error
		   FROM secret_rotation_schedules
		  WHERE tenant_id = $1 ORDER BY id`, tenantA)
	if err != nil {
		t.Fatalf("read migrated scheduler rows: %v", err)
	}
	defer rows.Close()
	want := map[string]string{
		"failed":          "scheduled rotation failed",
		"delivery_failed": "connector delivery failed",
	}
	seen := 0
	for rows.Next() {
		var status, detail string
		if err := rows.Scan(&status, &detail); err != nil {
			t.Fatalf("scan migrated scheduler row: %v", err)
		}
		if detail != want[status] || strings.Contains(detail, sensitive) {
			t.Fatalf("migrated %s detail = %q", status, detail)
		}
		seen++
	}
	if err := rows.Err(); err != nil || seen != len(want) {
		t.Fatalf("migrated scheduler row count=%d err=%v", seen, err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE secret_rotation_schedules SET last_error = $3
		  WHERE tenant_id = $1 AND id = $2`, tenantA,
		"16100000-0000-4000-8000-000000000011", sensitive); err == nil {
		t.Fatal("0161 accepted provider-controlled scheduler text after the scrub")
	}
}
