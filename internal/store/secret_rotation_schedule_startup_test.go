// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/rotationcommand"
	"trstctl.com/trstctl/internal/store"
)

func aud113StartupRegistrationResolver(
	context.Context,
	string,
) (string, uint64, error) {
	return testRotationTenantRegistrationID, testRotationTenantRegistrationSequence, nil
}

func TestSecretRotationScheduleStartupAuthorityRejectsRestoredClosedCursorAndMalformedReceiptAUD113(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	key := rotationcommand.OuterKeyV3Prefix + strings.Repeat("a", 64)
	const binding = "aud113-startup-authority-binding"

	seedRotationTickRegistration(t, s, tenantA)
	tick, state, err := s.ClaimSecretRotationScheduleTick(
		ctx, tenantA, key, binding,
		testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
		"aud113-startup-owner", "aud113-startup-child", time.Minute)
	if err != nil || state != store.SecretRotationScheduleTickAcquired || tick.SnapshotCount != 0 {
		t.Fatalf("claim empty startup-validation tick=%+v state=%q err=%v", tick, state, err)
	}
	if err := s.ValidateSecretRotationScheduleStartupAuthority(
		ctx, aud113StartupRegistrationResolver,
	); err != nil {
		t.Fatalf("valid live scheduler startup authority rejected: %v", err)
	}

	terminalBody := marshalRotationTickReceipt(t, rotationTickReceiptFixture{Complete: true})
	terminal, err := s.FinalizeSecretRotationScheduleTick(
		ctx, tick, tick.OwnerToken, tick.OwnerGeneration, 200, terminalBody, nil)
	if err != nil {
		t.Fatalf("finalize startup-validation tick: %v", err)
	}
	// The receiver is terminal before the generic idempotency owner caches the
	// protected result. This bound-outer/terminal-tick crash gap must stay bootable.
	if err := s.ValidateSecretRotationScheduleStartupAuthority(
		ctx, aud113StartupRegistrationResolver,
	); err != nil {
		t.Fatalf("valid terminal tick awaiting outer completion rejected: %v", err)
	}

	if _, err := s.SystemPool().Exec(ctx, `
		UPDATE secret_rotation_schedule_scan_cursors
		   SET active_tick_key = $2, active_tick_binding = $3,
		       lease_token = $4, lease_until = clock_timestamp() + interval '1 minute',
		       lease_generation = $5
		 WHERE tenant_id = $1`, tenantA, key, binding,
		"aud113-restored-owner", terminal.OwnerGeneration); err != nil {
		t.Fatalf("restore cursor-to-terminal fixture: %v", err)
	}
	if err := s.ValidateSecretRotationScheduleStartupAuthority(
		ctx, aud113StartupRegistrationResolver,
	); !errors.Is(
		err, store.ErrSecretRotationScheduleTickConflict,
	) {
		t.Fatalf("cursor-to-terminal startup error=%v, want tick authority conflict", err)
	}

	if _, err := s.SystemPool().Exec(ctx, `
		UPDATE secret_rotation_schedule_scan_cursors
		   SET active_tick_key = '', active_tick_binding = '',
		       lease_token = '', lease_until = NULL
		 WHERE tenant_id = $1`, tenantA); err != nil {
		t.Fatalf("clear restored terminal cursor: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx, `
		UPDATE secret_rotation_schedule_ticks
		   SET receipt = jsonb_set(receipt, '{ran}', '1'::jsonb)
		 WHERE tenant_id = $1 AND idempotency_key = $2`, tenantA, key); err != nil {
		t.Fatalf("restore malformed terminal receipt fixture: %v", err)
	}
	if err := s.ValidateSecretRotationScheduleStartupAuthority(
		ctx, aud113StartupRegistrationResolver,
	); !errors.Is(
		err, store.ErrSecretRotationScheduleTickConflict,
	) {
		t.Fatalf("malformed terminal startup error=%v, want tick authority conflict", err)
	}
}

func TestSecretRotationScheduleStartupAuthorityRejectsForgedRegistrationAndCommandOrdinalAUD113(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	cutoff := time.Date(2026, 8, 11, 19, 0, 0, 0, time.UTC)
	dueAt := cutoff.Add(-time.Minute)
	const (
		scheduleID = "a113a113-a113-4113-8113-a113a113a113"
		binding    = "aud113-linked-startup-binding"
	)
	key := rotationcommand.OuterKeyV3Prefix + strings.Repeat("b", 64)
	schedule := store.SecretRotationSchedule{
		ID: scheduleID, TenantID: tenantA, Name: "AUD-113 linked startup authority",
		Provider: "connector:ci", Key: "service/aud113", OldRef: "version:1",
		IntervalSeconds: 3600, ConfigEventSequence: 2,
		Enabled: true, NextRunAt: dueAt, CreatedAt: dueAt, UpdatedAt: dueAt,
	}
	seedSecretRotationSchedule(t, s, schedule)
	seedRotationTickRegistration(t, s, tenantA)

	tick, state, err := s.ClaimSecretRotationScheduleTick(
		ctx, tenantA, key, binding,
		testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
		"aud113-linked-owner", "aud113-linked-child", time.Minute)
	if err != nil || state != store.SecretRotationScheduleTickAcquired || tick.SnapshotCount != 1 {
		t.Fatalf("claim linked startup-validation tick=%+v state=%q err=%v", tick, state, err)
	}
	row, err := s.GetSecretRotationScheduleTickRow(ctx, tenantA, key, 1)
	if err != nil {
		t.Fatalf("load linked startup-validation row: %v", err)
	}
	const childLease = "aud113-linked-command-lease"
	tick, err = s.StartSecretRotationScheduleTickRow(
		ctx, tick, tick.OwnerToken, tick.OwnerGeneration, row, childLease, time.Minute)
	if err != nil {
		t.Fatalf("start linked startup-validation row: %v", err)
	}
	runID := orchestrator.SecretRotationScheduleRunID(
		tenantA, testRotationTenantRegistrationSequence, row.ID, row.NextRunAt)
	command := store.SecretRotationScheduleCommand{
		TenantID: tenantA, IdentityVersion: store.SecretRotationScheduleIdentityVersion,
		TenantRegistrationEventID:       testRotationTenantRegistrationID,
		TenantRegistrationEventSequence: testRotationTenantRegistrationSequence,
		ScheduleID:                      row.ID,
		RunID:                           runID,
		DueAt:                           row.NextRunAt,
		Provider:                        row.Provider,
		Key:                             row.Key,
		OldRef:                          row.OldRef,
		IntervalSeconds:                 row.IntervalSeconds,
		ConfigEventSequence:             row.ConfigEventSequence,
		TickIdempotencyKey:              key,
		TickOrdinal:                     1,
		CommandKey:                      orchestrator.SecretRotationScheduleCommandKey(runID),
		RequestBinding:                  "aud113-linked-command-binding",
		TerminalEventID:                 orchestrator.SecretRotationScheduleRunEventID(runID),
	}
	claimed, acquired, err := s.ClaimSecretRotationScheduleCommand(
		ctx, command, childLease, time.Minute)
	if err != nil || !acquired {
		t.Fatalf("claim linked startup-validation command=%+v acquired=%t err=%v",
			claimed, acquired, err)
	}
	if err := s.ValidateSecretRotationScheduleStartupAuthority(
		ctx, aud113StartupRegistrationResolver,
	); err != nil {
		t.Fatalf("valid linked scheduler startup authority rejected: %v", err)
	}

	const forgedEventID = "aud113-forged-registration-at-live-sequence"
	if _, err := s.SystemPool().Exec(ctx, `
		UPDATE secret_rotation_schedule_ticks
		   SET tenant_registration_event_id = $3
		 WHERE tenant_id = $1 AND idempotency_key = $2`, tenantA, key, forgedEventID); err != nil {
		t.Fatalf("forge tick and cascaded row registration id: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx, `
		UPDATE secret_rotation_schedule_commands
		   SET tenant_registration_event_id = $4
		 WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3`,
		tenantA, scheduleID, runID, forgedEventID); err != nil {
		t.Fatalf("forge command registration id: %v", err)
	}
	if err := s.ValidateSecretRotationScheduleStartupAuthority(
		ctx, aud113StartupRegistrationResolver,
	); !errors.Is(err, store.ErrSecretRotationScheduleTickConflict) {
		t.Fatalf("mutually forged registration startup error=%v, want tick authority conflict", err)
	}
	if _, err := s.SystemPool().Exec(ctx, `
		UPDATE secret_rotation_schedule_ticks
		   SET tenant_registration_event_id = $3
		 WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, key, testRotationTenantRegistrationID); err != nil {
		t.Fatalf("restore tick and cascaded row registration id: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx, `
		UPDATE secret_rotation_schedule_commands
		   SET tenant_registration_event_id = $4
		 WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3`,
		tenantA, scheduleID, runID, testRotationTenantRegistrationID); err != nil {
		t.Fatalf("restore command registration id: %v", err)
	}
	if err := s.ValidateSecretRotationScheduleStartupAuthority(
		ctx, aud113StartupRegistrationResolver,
	); err != nil {
		t.Fatalf("restored exact registration authority rejected: %v", err)
	}

	if _, err := s.SystemPool().Exec(ctx, `
		UPDATE secret_rotation_schedule_commands
		   SET tick_ordinal = 2, provider = 'connector:forged'
		 WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3`,
		tenantA, scheduleID, runID); err != nil {
		t.Fatalf("forge retained command ordinal and tuple: %v", err)
	}
	if err := s.ValidateSecretRotationScheduleStartupAuthority(
		ctx, aud113StartupRegistrationResolver,
	); !errors.Is(err, store.ErrSecretRotationScheduleCommandConflict) {
		t.Fatalf("forged retained command ordinal startup error=%v, want command conflict", err)
	}
	if _, err := s.SystemPool().Exec(ctx, `
		UPDATE secret_rotation_schedule_commands
		   SET tick_ordinal = 1, provider = $4
		 WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3`,
		tenantA, scheduleID, runID, row.Provider); err != nil {
		t.Fatalf("restore retained command ordinal and tuple: %v", err)
	}
	if err := s.ValidateSecretRotationScheduleStartupAuthority(
		ctx, aud113StartupRegistrationResolver,
	); err != nil {
		t.Fatalf("restored exact command ordinal rejected: %v", err)
	}

	run := terminalScheduleRunForTest(
		claimed, "queued", "version:2", cutoff.Add(time.Second), 11301,
		strings.Repeat("d", 64))
	applyScheduleRunForTest(t, s, run)
	if _, err := s.SystemPool().Exec(ctx, `
		DELETE FROM idempotency_keys
		 WHERE tenant_id = $1 AND key = $2`, tenantA, key); err != nil {
		t.Fatalf("garbage-collect terminal aggregate tick: %v", err)
	}
	if err := s.ValidateSecretRotationScheduleStartupAuthority(
		ctx, aud113StartupRegistrationResolver,
	); err != nil {
		t.Fatalf("terminal command whose aggregate tick was garbage-collected rejected: %v", err)
	}
}

func TestSecretRotationScheduleStartupAuthorityAllowsUnanchoredConfigSnapshotAUD113(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	cutoff := time.Now().UTC().Add(-time.Minute)
	const (
		scheduleID = "b113b113-b113-4113-8113-b113b113b113"
		binding    = "aud113-unanchored-config-binding"
	)
	key := rotationcommand.OuterKeyV3Prefix + strings.Repeat("c", 64)
	seedRotationTickRegistration(t, s, tenantA)
	schedule := store.SecretRotationSchedule{
		ID: scheduleID, TenantID: tenantA, Name: "AUD-113 migrated unanchored config",
		Provider: "connector:ci", Key: "service/unanchored", OldRef: "version:1",
		IntervalSeconds: 3600, ConfigEventSequence: 0,
		Enabled: true, NextRunAt: cutoff.Add(-time.Minute),
		CreatedAt: cutoff.Add(-time.Minute), UpdatedAt: cutoff.Add(-time.Minute),
	}
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretRotationScheduleUpsertedTx(ctx, tx, schedule)
	}); err != nil {
		t.Fatalf("seed unanchored scheduler configuration: %v", err)
	}
	tick, state, err := s.ClaimSecretRotationScheduleTick(
		ctx, tenantA, key, binding,
		testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
		"aud113-unanchored-owner", "aud113-unanchored-child", time.Minute)
	if err != nil || state != store.SecretRotationScheduleTickAcquired || tick.SnapshotCount != 1 {
		t.Fatalf("claim unanchored-config tick=%+v state=%q err=%v", tick, state, err)
	}
	row, err := s.GetSecretRotationScheduleTickRow(ctx, tenantA, key, 1)
	if err != nil || row.ConfigEventSequence != 0 {
		t.Fatalf("unanchored snapshot row=%+v err=%v, want retained revision zero", row, err)
	}
	if err := s.ValidateSecretRotationScheduleStartupAuthority(
		ctx, aud113StartupRegistrationResolver,
	); err != nil {
		t.Fatalf("intentional config_revision_unanchored snapshot rejected: %v", err)
	}
}
