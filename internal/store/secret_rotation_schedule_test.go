// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const (
	// Historical tenant.registered IDs were plain UUIDs. Scheduler lifecycle
	// validation must retain them verbatim; it may not require a newer prefix.
	testRotationTenantRegistrationID       = "15500000-0000-4000-8000-000000000001"
	testRotationTenantRegistrationSequence = uint64(1)
)

func TestSecretRotationSchedulePromotesOnlyExplicitCommittedSuccessorStatus(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	base := time.Date(2026, 8, 10, 19, 0, 0, 0, time.UTC)
	const scheduleID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretRotationScheduleUpsertedTx(ctx, tx, store.SecretRotationSchedule{
			ID: scheduleID, TenantID: tenantA, Name: "explicit-phase-authority",
			Provider: "static", Key: "database/password", OldRef: "old-ref",
			IntervalSeconds: 3600, Enabled: true, NextRunAt: base,
			CreatedAt: base, UpdatedAt: base,
		})
	})
	if err != nil {
		t.Fatalf("seed rotation schedule: %v", err)
	}

	// A non-empty new_ref is not proof that a stage/cutover committed. Generic
	// failure must keep the prior authority exactly as-is.
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretRotationScheduleRunTx(ctx, tx, store.SecretRotationScheduleRun{
			TenantID: tenantA, ScheduleID: scheduleID,
			RunID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", Status: "failed",
			NewRef: "never-live", Error: "stage failed", RanAt: base.Add(time.Minute),
		})
	})
	if err != nil {
		t.Fatalf("project generic failed run: %v", err)
	}
	got, err := s.GetSecretRotationSchedule(ctx, tenantA, scheduleID)
	if err != nil || got.OldRef != "old-ref" || got.LastNewRef != "never-live" {
		t.Fatalf("generic failure promoted inferred successor: %+v err=%v", got, err)
	}

	// retire_pending is explicit phase authority: cutover and verification are
	// complete, so later cadences must use the live successor while cleanup retries.
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretRotationScheduleRunTx(ctx, tx, store.SecretRotationScheduleRun{
			TenantID: tenantA, ScheduleID: scheduleID,
			RunID: "cccccccc-cccc-cccc-cccc-cccccccccccc", Status: "retire_pending",
			NewRef: "live-successor", Error: "retire failed", RanAt: base.Add(2 * time.Minute),
		})
	})
	if err != nil {
		t.Fatalf("project retire-pending run: %v", err)
	}
	got, err = s.GetSecretRotationSchedule(ctx, tenantA, scheduleID)
	if err != nil || got.OldRef != "live-successor" || got.LastRunStatus != "retire_pending" {
		t.Fatalf("explicit live successor was not promoted: %+v err=%v", got, err)
	}
}

func TestSecretRotationScheduleCommandClaimBindsExactAggregateChildAndResume(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	dueAt := time.Date(2026, 8, 11, 10, 0, 0, 0, time.UTC)
	const scheduleID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaa155"
	seedSecretRotationSchedule(t, s, store.SecretRotationSchedule{
		ID: scheduleID, TenantID: tenantA, Name: "overlap", Provider: "connector:ci",
		Key: "app/password", OldRef: "version:1", IntervalSeconds: 3600,
		Enabled: true, NextRunAt: dueAt, CreatedAt: dueAt, UpdatedAt: dueAt,
	})
	command := claimScheduleCommandForTest(t, s, tenantA, scheduleID, "connector:ci",
		"app/password", "version:1", dueAt, "overlap")
	runID := command.RunID
	const aggregateLease = "lease-overlap"
	recovered, acquired, err := s.ClaimSecretRotationScheduleCommand(
		ctx, command, aggregateLease, time.Minute)
	if err != nil || !acquired || recovered.ClaimState != store.SecretRotationScheduleCommandRecovered {
		t.Fatalf("same aggregate child resume=%+v acquired=%t err=%v", recovered, acquired, err)
	}
	if _, _, err := s.ClaimSecretRotationScheduleCommand(
		ctx, command, "other-aggregate-lease", time.Minute); !errors.Is(err, store.ErrSecretRotationScheduleCommandConflict) {
		t.Fatalf("other aggregate child lease error=%v, want command conflict", err)
	}
	if err := s.ReleaseSecretRotationScheduleCommandLease(
		ctx, tenantA, scheduleID, runID, "stale-runner"); !errors.Is(err, store.ErrSecretRotationScheduleCommandConflict) {
		t.Fatalf("release with stale token error=%v, want command conflict", err)
	}
	stillLeased, err := s.GetSecretRotationScheduleCommand(ctx, tenantA, scheduleID, runID)
	if err != nil || stillLeased.LeaseToken != aggregateLease || stillLeased.LeaseUntil == nil {
		t.Fatalf("stale release changed winner lease: command=%+v err=%v", stillLeased, err)
	}
	if err := s.ReleaseSecretRotationScheduleCommandLease(ctx, tenantA, scheduleID, runID, aggregateLease); err != nil {
		t.Fatalf("release winner lease: %v", err)
	}
	got, resumed, err := s.ClaimSecretRotationScheduleCommand(
		ctx, command, aggregateLease, time.Minute)
	if err != nil || !resumed || got.RunID != runID || got.CommandKey != command.CommandKey {
		t.Fatalf("exact replacement claim=%+v acquired=%t err=%v", got, resumed, err)
	}
	drifted := command
	drifted.OldRef = "version:99"
	if _, _, err := s.ClaimSecretRotationScheduleCommand(
		ctx, drifted, "drifted-runner", time.Minute); !errors.Is(err, store.ErrSecretRotationScheduleCommandConflict) {
		t.Fatalf("drifted command error=%v, want retained-authority conflict", err)
	}
}

func TestSecretRotationScheduleTerminalProjectionIsDueEdgeMonotonic(t *testing.T) {
	for _, tc := range []struct {
		name       string
		provider   string
		status     string
		firstRef   string
		secondRef  string
		scheduleID string
	}{
		{name: "historical static", provider: "static", status: "completed", firstRef: "static-v2", secondRef: "static-v3", scheduleID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbb155"},
		{name: "connector", provider: "connector:ci", status: "queued", firstRef: "version:2", secondRef: "version:3", scheduleID: "cccccccc-cccc-4ccc-8ccc-ccccccccc155"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			seedTwoTenants(t, s)
			ctx := context.Background()
			dueAt := time.Date(2026, 8, 11, 11, 0, 0, 0, time.UTC)
			seedSecretRotationSchedule(t, s, store.SecretRotationSchedule{
				ID: tc.scheduleID, TenantID: tenantA, Name: tc.name, Provider: tc.provider,
				Key: "service/password", OldRef: "version:1", IntervalSeconds: 60,
				Enabled: true, NextRunAt: dueAt, CreatedAt: dueAt, UpdatedAt: dueAt,
			})

			firstCommand := claimScheduleCommandForTest(t, s, tenantA, tc.scheduleID, tc.provider,
				"service/password", "version:1", dueAt, "first")
			firstRun := terminalScheduleRunForTest(firstCommand, tc.status, tc.firstRef,
				dueAt.Add(time.Second), 15501, strings.Repeat("a", 64))
			applyScheduleRunForTest(t, s, firstRun)
			if err := s.ReleaseSecretRotationScheduleCommandLease(
				ctx, tenantA, tc.scheduleID, firstCommand.RunID, "lease-first"); err != nil {
				t.Fatalf("terminalized command release should be a proven no-op: %v", err)
			}
			firstAfter, err := s.GetSecretRotationSchedule(ctx, tenantA, tc.scheduleID)
			if err != nil {
				t.Fatal(err)
			}

			secondCommand := claimScheduleCommandForTest(t, s, tenantA, tc.scheduleID, tc.provider,
				"service/password", tc.firstRef, firstAfter.NextRunAt, "second")
			secondRun := terminalScheduleRunForTest(secondCommand, tc.status, tc.secondRef,
				firstAfter.NextRunAt.Add(time.Second), 15502, strings.Repeat("b", 64))
			applyScheduleRunForTest(t, s, secondRun)
			applyScheduleRunForTest(t, s, firstRun) // reverse/duplicate older projection

			got, err := s.GetSecretRotationSchedule(ctx, tenantA, tc.scheduleID)
			if err != nil || got.OldRef != tc.secondRef || got.LastRunID == nil || *got.LastRunID != secondCommand.RunID ||
				got.LastRunStatus != tc.status || !got.NextRunAt.After(firstAfter.NextRunAt) {
				t.Fatalf("reverse terminal projection regressed schedule: %+v err=%v", got, err)
			}
		})
	}
}

func TestSecretRotationScheduleTerminalProjectionRollsBackOnDueEdgeCASMiss(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	dueAt := time.Date(2026, 8, 11, 11, 30, 0, 0, time.UTC)
	const scheduleID = "f0f0f0f0-f0f0-40f0-80f0-f0f0f0f0f155"
	seedSecretRotationSchedule(t, s, store.SecretRotationSchedule{
		ID: scheduleID, TenantID: tenantA, Name: "cas-drift", Provider: "connector:ci",
		Key: "service/drift", OldRef: "version:1", IntervalSeconds: 60,
		Enabled: true, NextRunAt: dueAt, CreatedAt: dueAt, UpdatedAt: dueAt,
	})
	command := claimScheduleCommandForTest(t, s, tenantA, scheduleID, "connector:ci",
		"service/drift", "version:1", dueAt, "cas-drift")

	// Simulate a newer schedule projection replacing the exact edge after the
	// runner claimed it but before its terminal event projects.
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE secret_rotation_schedules
			    SET next_run_at = $3
			  WHERE tenant_id = $1 AND id = $2`, tenantA, scheduleID, dueAt.Add(time.Minute))
		return err
	}); err != nil {
		t.Fatalf("drift schedule due edge: %v", err)
	}
	run := terminalScheduleRunForTest(command, "queued", "version:2",
		dueAt.Add(time.Second), 15503, strings.Repeat("c", 64))
	if _, err := s.PrepareSecretRotationScheduleCommandTerminal(ctx, run); err != nil {
		t.Fatalf("prepare drifted terminal intent: %v", err)
	}
	err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretRotationScheduleRunTx(ctx, tx, run)
	})
	if !errors.Is(err, store.ErrSecretRotationScheduleCommandConflict) {
		t.Fatalf("drifted terminal projection error=%v, want exact CAS conflict", err)
	}
	retained, err := s.GetSecretRotationScheduleCommand(ctx, tenantA, scheduleID, command.RunID)
	if err != nil || retained.Status != "claimed" || retained.TerminalEventSequence != nil {
		t.Fatalf("CAS miss manufactured terminal command authority: %+v err=%v", retained, err)
	}
	schedule, err := s.GetSecretRotationSchedule(ctx, tenantA, scheduleID)
	if err != nil || schedule.LastRunID != nil || !schedule.NextRunAt.Equal(dueAt.Add(time.Minute)) {
		t.Fatalf("CAS miss mutated drifted schedule: %+v err=%v", schedule, err)
	}
}

func TestMigration0155RefusesApplicationRoleTerminalForgery(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	dueAt := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	const scheduleID = "dddddddd-dddd-4ddd-8ddd-ddddddddd155"
	seedSecretRotationSchedule(t, s, store.SecretRotationSchedule{
		ID: scheduleID, TenantID: tenantA, Name: "terminal-guard", Provider: "connector:ci",
		Key: "guard/password", OldRef: "version:1", IntervalSeconds: 60,
		Enabled: true, NextRunAt: dueAt, CreatedAt: dueAt, UpdatedAt: dueAt,
	})
	runID := orchestrator.SecretRotationScheduleRunID(
		tenantA, testRotationTenantRegistrationSequence, scheduleID, dueAt)
	eventID := orchestrator.SecretRotationScheduleRunEventID(runID)

	err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO secret_rotation_schedule_commands
			        (tenant_id, schedule_id, run_id, due_at, provider, secret_key,
			         old_ref, interval_seconds, config_event_sequence,
			         tick_idempotency_key, tick_ordinal,
			         command_key, request_binding, terminal_event_id,
			         prepared_status, prepared_event_digest, prepared_at,
			         terminal_event_type, terminal_event_sequence, terminal_event_digest,
			         terminal_event_from_event, status, created_at, updated_at, terminal_at)
			 VALUES ($1, $2, $3, $4, 'connector:ci', 'guard/password', 'version:1',
			         60, 1, 'forged-tick', 1,
			         'forged-command', 'forged-binding', $5, 'queued', $6, $7,
			         'secret.rotation_schedule.ran', 155, $6, true, 'queued', $7, $7, $7)`,
			tenantA, scheduleID, runID, dueAt, eventID, strings.Repeat("f", 64), dueAt)
		return err
	})
	if err == nil {
		t.Fatal("trstctl_app inserted a terminal schedule receipt directly")
	}

	command := claimScheduleCommandForTest(t, s, tenantA, scheduleID, "connector:ci",
		"guard/password", "version:1", dueAt, "claim")
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM secret_rotation_schedule_commands
			  WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3`,
			tenantA, scheduleID, command.RunID)
		return err
	})
	if err == nil {
		t.Fatal("trstctl_app deleted durable schedule command authority directly")
	}
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE secret_rotation_schedule_commands
			    SET status = 'queued', terminal_at = now(),
			        terminal_event_type = 'secret.rotation_schedule.ran',
			        terminal_event_sequence = 155, terminal_event_digest = $4,
			        terminal_event_from_event = true
			  WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3`,
			tenantA, scheduleID, command.RunID, strings.Repeat("e", 64))
		return err
	})
	if err == nil {
		t.Fatal("trstctl_app updated a claimed command to terminal directly")
	}

	const otherScheduleID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeee155"
	seedSecretRotationSchedule(t, s, store.SecretRotationSchedule{
		ID: otherScheduleID, TenantID: tenantA, Name: "null-sequence-guard", Provider: "connector:ci",
		Key: "guard/other", OldRef: "version:1", IntervalSeconds: 60,
		Enabled: true, NextRunAt: dueAt, CreatedAt: dueAt, UpdatedAt: dueAt,
	})
	otherRunID := orchestrator.SecretRotationScheduleRunID(
		tenantA, testRotationTenantRegistrationSequence, otherScheduleID, dueAt)
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO secret_rotation_schedule_commands
		        (tenant_id, schedule_id, run_id, due_at, provider, secret_key,
		         old_ref, interval_seconds, config_event_sequence,
		         tick_idempotency_key, tick_ordinal,
		         command_key, request_binding, terminal_event_id,
		         prepared_status, prepared_event_digest, prepared_at,
		         terminal_event_type, terminal_event_sequence, terminal_event_digest,
		         terminal_event_from_event, status, created_at, updated_at, terminal_at)
		 VALUES ($1, $2, $3, $4, 'connector:ci', 'guard/other', 'version:1',
		         60, 1, 'owner-forged-tick', 1,
		         'owner-forged-command', 'owner-forged-binding', $5, 'queued', $6, $7,
		         'secret.rotation_schedule.ran', NULL, $6, true, 'queued', $7, $7, $7)`,
		tenantA, otherScheduleID, otherRunID, dueAt,
		orchestrator.SecretRotationScheduleRunEventID(otherRunID), strings.Repeat("d", 64), dueAt); err == nil {
		t.Fatal("0155 accepted terminal evidence with a NULL event sequence")
	}
}

func TestSecretRotationSchedulePrivacySequentialErasureRequiresCompletedPriorOperation(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	const (
		scheduleID      = "abababab-abab-4bab-8bab-ababababa155"
		runID           = "cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdc155"
		terminalEventID = "efefefef-efef-4fef-8fef-efefefefe155"
	)
	firstSubjectRef := privacy.SubjectRef(tenantA, "alice")
	secondSubjectRef := privacy.SubjectRef(tenantA, "bob")
	firstOperationID := "sha256:" + strings.Repeat("a", 60) + "0155"
	firstEventID := "sha256:" + strings.Repeat("b", 60) + "0155"
	secondOperationID := "sha256:" + strings.Repeat("c", 60) + "0155"
	secondEventID := "sha256:" + strings.Repeat("d", 60) + "0155"
	providerBefore := "connector:" + privacy.Placeholder(firstSubjectRef) + "/bob"

	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO secret_rotation_schedule_scan_cursors (tenant_id) VALUES ($1)`, tenantA); err != nil {
		t.Fatalf("seed scheduler cursor: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO secret_rotation_schedule_commands
		        (tenant_id, schedule_id, run_id, due_at, provider, secret_key, old_ref,
		         interval_seconds, config_event_sequence, tick_idempotency_key, tick_ordinal,
		         command_key, request_binding, terminal_event_id,
		         privacy_rewrite_version, privacy_subject_ref,
		         privacy_operation_id, privacy_event_id,
		         status, created_at, updated_at, terminal_at)
		 VALUES ($1, $2, $3, clock_timestamp(), $4, 'vault', 'version:1',
		         60, 1, 'closed-tick', 1, 'closed-command', 'closed-binding', $5,
		         1, $6, $7, $8, 'privacy_erased',
		         clock_timestamp(), clock_timestamp(), clock_timestamp())`,
		tenantA, scheduleID, runID, providerBefore, terminalEventID,
		firstSubjectRef, firstOperationID, firstEventID); err != nil {
		t.Fatalf("seed previously privacy-erased command: %v", err)
	}

	prepare := func() (store.SecretRotationSchedulePrivacyPreparation, error) {
		var result store.SecretRotationSchedulePrivacyPreparation
		err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			var err error
			result, err = s.PrepareSecretRotationSchedulePrivacyErasureTx(
				ctx, tx, tenantA, "bob", secondSubjectRef, secondOperationID, secondEventID, nil)
			return err
		})
		return result, err
	}
	if _, err := prepare(); !errors.Is(err, store.ErrSecretRotationScheduleCommandConflict) {
		t.Fatalf("sequential erasure without completed prior operation error=%v, want command conflict", err)
	}

	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO privacy_subject_erasure_operations
		        (tenant_id, operation_id, request_binding, event_id, event_sequence,
		         subject_ref, selectors, counts, erased_at)
		 VALUES ($1, $2, 'prior-binding', $3, 1, $4, '{}'::jsonb, '{}'::jsonb, clock_timestamp())`,
		tenantA, firstOperationID, firstEventID, firstSubjectRef); err != nil {
		t.Fatalf("seed completed prior privacy operation: %v", err)
	}
	result, err := prepare()
	if err != nil || result.Commands != 1 || len(result.Dispositions) != 1 {
		t.Fatalf("sequential privacy preparation=%+v err=%v", result, err)
	}

	var providerAfter, subjectRefAfter, operationIDAfter, eventIDAfter string
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT provider, privacy_subject_ref, privacy_operation_id, privacy_event_id
		   FROM secret_rotation_schedule_commands
		  WHERE tenant_id = $1 AND run_id = $2`, tenantA, runID).Scan(
		&providerAfter, &subjectRefAfter, &operationIDAfter, &eventIDAfter); err != nil {
		t.Fatalf("load sequentially rewritten command: %v", err)
	}
	wantProvider := "connector:" + privacy.Placeholder(firstSubjectRef) + "/" + privacy.Placeholder(secondSubjectRef)
	if providerAfter != wantProvider || subjectRefAfter != secondSubjectRef ||
		operationIDAfter != secondOperationID || eventIDAfter != secondEventID {
		t.Fatalf("latest sequential privacy stamp = (%q, %q, %q, %q), want (%q, %q, %q, %q)",
			providerAfter, subjectRefAfter, operationIDAfter, eventIDAfter,
			wantProvider, secondSubjectRef, secondOperationID, secondEventID)
	}

	retry, err := prepare()
	if err != nil || retry.Commands != 0 || retry.Ticks != 0 || retry.TickRows != 0 {
		t.Fatalf("converged privacy retry=%+v err=%v, want no selected rows", retry, err)
	}
}

func seedSecretRotationSchedule(t *testing.T, s *store.Store, schedule store.SecretRotationSchedule) {
	t.Helper()
	if _, err := s.SystemPool().Exec(context.Background(),
		`UPDATE tenants SET event_seq = $2 WHERE tenant_id = $1`,
		schedule.TenantID, testRotationTenantRegistrationSequence); err != nil {
		t.Fatalf("seed scheduler tenant registration sequence: %v", err)
	}
	if schedule.ConfigEventSequence == 0 {
		schedule.ConfigEventSequence = 2
	}
	if err := s.WithTenantProjection(context.Background(), schedule.TenantID, func(tx pgx.Tx) error {
		return s.ApplySecretRotationScheduleUpsertedTx(context.Background(), tx, schedule)
	}); err != nil {
		t.Fatalf("seed secret rotation schedule: %v", err)
	}
}

func claimScheduleCommandForTest(
	t *testing.T,
	s *store.Store,
	tenantID, scheduleID, provider, key, oldRef string,
	dueAt time.Time,
	suffix string,
) store.SecretRotationScheduleCommand {
	t.Helper()
	ctx := context.Background()
	schedule, err := s.GetSecretRotationSchedule(ctx, tenantID, scheduleID)
	if err != nil {
		t.Fatalf("load schedule for command fixture: %v", err)
	}
	runID := orchestrator.SecretRotationScheduleRunID(
		tenantID, testRotationTenantRegistrationSequence, scheduleID, dueAt)
	tickKey := "tick-" + suffix
	tickBinding := "tick-binding-" + suffix
	tickOwner := "tick-owner-" + suffix
	commandLease := "lease-" + suffix
	initialReceipt := `{"ran":0,"scanned":0,"runs":[],"deferred":[],"run_limit_reached":false,"scan_limit_reached":false,"complete":false,"partial":false}`
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO idempotency_keys (tenant_id, key, status, request_binding)
		 VALUES ($1, $2, 'bound', $3)`, tenantID, tickKey, tickBinding); err != nil {
		t.Fatalf("seed scheduler outer command: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO secret_rotation_schedule_scan_cursors
		        (tenant_id, active_tick_key, active_tick_binding, lease_token,
		         lease_until, lease_generation, generation)
		 VALUES ($1, $2, $3, $4, clock_timestamp() + interval '1 hour', 1, 0)
		 ON CONFLICT (tenant_id) DO UPDATE
		 SET active_tick_key = EXCLUDED.active_tick_key,
		     active_tick_binding = EXCLUDED.active_tick_binding,
		     lease_token = EXCLUDED.lease_token,
		     lease_until = EXCLUDED.lease_until,
		     lease_generation = secret_rotation_schedule_scan_cursors.lease_generation + 1`,
		tenantID, tickKey, tickBinding, tickOwner); err != nil {
		t.Fatalf("seed scheduler cursor: %v", err)
	}
	var ownerGeneration int64
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT lease_generation FROM secret_rotation_schedule_scan_cursors WHERE tenant_id = $1`,
		tenantID).Scan(&ownerGeneration); err != nil {
		t.Fatalf("read scheduler cursor generation: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO secret_rotation_schedule_ticks
		        (tenant_id, identity_version, tenant_registration_event_id,
		         tenant_registration_event_sequence,
		         idempotency_key, request_binding, due_through,
		         start_schedule_id, after_schedule_id, phase,
		         current_schedule_id, current_due_at, current_provider,
		         current_secret_key, current_old_ref, current_interval_seconds,
		         current_config_event_sequence, current_command_lease_token,
		         snapshot_count, receipt, owner_token, owner_generation,
		         created_at, updated_at)
		 VALUES ($1, 3, $2, $3, $4, $5, $6, $7, $7, 'row_started',
		         $7, $6, $8, $9, $10, $11, $12, $13,
		         1, $14::jsonb, $15, $16, clock_timestamp(), clock_timestamp())`,
		tenantID, testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
		tickKey, tickBinding, dueAt, scheduleID,
		provider, key, oldRef, schedule.IntervalSeconds, schedule.ConfigEventSequence,
		commandLease, initialReceipt, tickOwner, ownerGeneration); err != nil {
		t.Fatalf("seed scheduler tick: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO secret_rotation_schedule_tick_rows
		        (tenant_id, identity_version, tenant_registration_event_id,
		         tenant_registration_event_sequence,
		         idempotency_key, ordinal, schedule_id, due_at,
		         provider, secret_key, old_ref, interval_seconds, config_event_sequence)
		 VALUES ($1, 3, $2, $3, $4, 1, $5, $6, $7, $8, $9, $10, $11)`,
		tenantID, testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
		tickKey, scheduleID, dueAt, provider, key, oldRef,
		schedule.IntervalSeconds, schedule.ConfigEventSequence); err != nil {
		t.Fatalf("seed scheduler tick row: %v", err)
	}
	command := store.SecretRotationScheduleCommand{
		TenantID: tenantID, IdentityVersion: store.SecretRotationScheduleIdentityVersion,
		TenantRegistrationEventID:       testRotationTenantRegistrationID,
		TenantRegistrationEventSequence: testRotationTenantRegistrationSequence,
		ScheduleID:                      scheduleID, RunID: runID, DueAt: dueAt,
		Provider: provider, Key: key, OldRef: oldRef,
		IntervalSeconds: schedule.IntervalSeconds, ConfigEventSequence: schedule.ConfigEventSequence,
		TickIdempotencyKey: tickKey, TickOrdinal: 1,
		CommandKey:     orchestrator.SecretRotationScheduleCommandKey(runID),
		RequestBinding: "binding-" + suffix, TerminalEventID: orchestrator.SecretRotationScheduleRunEventID(runID),
	}
	got, acquired, err := s.ClaimSecretRotationScheduleCommand(ctx, command, commandLease, time.Minute)
	if err != nil || !acquired {
		t.Fatalf("claim schedule command: got=%+v acquired=%t err=%v", got, acquired, err)
	}
	return got
}

func terminalScheduleRunForTest(
	command store.SecretRotationScheduleCommand,
	status, newRef string,
	ranAt time.Time,
	sequence uint64,
	digest string,
) store.SecretRotationScheduleRun {
	return store.SecretRotationScheduleRun{
		TenantID: command.TenantID, IdentityVersion: command.IdentityVersion,
		TenantRegistrationEventID:       command.TenantRegistrationEventID,
		TenantRegistrationEventSequence: command.TenantRegistrationEventSequence,
		ScheduleID:                      command.ScheduleID, RunID: command.RunID,
		SchemaVersion: projections.SecretRotationScheduleRanEventSchemaVersion,
		DueAt:         command.DueAt, Provider: command.Provider, Key: command.Key,
		OldRef: command.OldRef, IntervalSeconds: command.IntervalSeconds,
		ConfigEventSequence: command.ConfigEventSequence, CommandKey: command.CommandKey,
		RequestBinding: command.RequestBinding,
		Status:         status, NewRef: newRef, RanAt: ranAt,
		EventID: command.TerminalEventID, EventType: "secret.rotation_schedule.ran",
		EventSequence: sequence, EventDigest: digest,
		TickIdempotencyKey: command.TickIdempotencyKey, TickOrdinal: command.TickOrdinal,
		LeaseToken: command.LeaseToken,
	}
}

func applyScheduleRunForTest(t *testing.T, s *store.Store, run store.SecretRotationScheduleRun) {
	t.Helper()
	if _, err := s.PrepareSecretRotationScheduleCommandTerminal(context.Background(), run); err != nil {
		t.Fatalf("prepare schedule run %+v: %v", run, err)
	}
	if err := s.WithTenantProjection(context.Background(), run.TenantID, func(tx pgx.Tx) error {
		return s.ApplySecretRotationScheduleRunTx(context.Background(), tx, run)
	}); err != nil {
		t.Fatalf("apply schedule run %+v: %v", run, err)
	}
	tick, err := s.GetSecretRotationScheduleTick(context.Background(), run.TenantID, run.TickIdempotencyKey)
	if err != nil {
		t.Fatalf("load terminalized scheduler tick: %v", err)
	}
	runReceipt, err := json.Marshal(map[string]any{
		"schedule_id": run.ScheduleID, "run_id": run.RunID, "due_at": run.DueAt,
		"status": run.Status, "rotation": map[string]any{
			"key": run.Key, "old_ref": run.OldRef, "new_ref": run.NewRef,
			"completed": run.Status == "completed", "queued": run.Status == "queued",
			"rolled_back": false, "rollback_attempted": false, "rollback_failed": false,
		}, "ran_at": run.RanAt, "reconciled": false,
	})
	if err != nil {
		t.Fatalf("marshal exact scheduler run receipt: %v", err)
	}
	progress, err := json.Marshal(rotationTickReceiptFixture{
		Ran: 1, Scanned: 1, Runs: []json.RawMessage{runReceipt},
	})
	if err != nil {
		t.Fatalf("marshal scheduler progress: %v", err)
	}
	tick, err = s.CompleteSecretRotationScheduleTickRow(
		context.Background(), tick, tick.OwnerToken, tick.OwnerGeneration,
		progress, 1, 1, nil, time.Minute)
	if err != nil {
		t.Fatalf("complete scheduler tick row: %v", err)
	}
	terminal, err := json.Marshal(rotationTickReceiptFixture{
		Ran: 1, Scanned: 1, Runs: []json.RawMessage{runReceipt}, Complete: true,
	})
	if err != nil {
		t.Fatalf("marshal scheduler terminal receipt: %v", err)
	}
	if _, err := s.FinalizeSecretRotationScheduleTick(
		context.Background(), tick, tick.OwnerToken, tick.OwnerGeneration, 200, terminal, nil); err != nil {
		t.Fatalf("finalize scheduler tick: %v", err)
	}
}
