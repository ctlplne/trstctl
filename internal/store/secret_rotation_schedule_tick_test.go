// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/idemgc"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type rotationTickReceiptFixture struct {
	Ran              int               `json:"ran"`
	Scanned          int               `json:"scanned"`
	Runs             []json.RawMessage `json:"runs"`
	Deferred         []json.RawMessage `json:"deferred"`
	RunLimitReached  bool              `json:"run_limit_reached"`
	ScanLimitReached bool              `json:"scan_limit_reached"`
	Complete         bool              `json:"complete"`
	Partial          bool              `json:"partial"`
	FailedScheduleID string            `json:"failed_schedule_id,omitempty"`
	SystemError      string            `json:"system_error,omitempty"`
}

func seedBoundRotationTickKey(
	t *testing.T,
	s *store.Store,
	tenantID, key, binding string,
	createdAt time.Time,
) {
	t.Helper()
	if _, err := s.SystemPool().Exec(context.Background(),
		`UPDATE tenants SET event_seq = $2 WHERE tenant_id = $1`,
		tenantID, testRotationTenantRegistrationSequence); err != nil {
		t.Fatalf("seed scheduler tenant registration sequence: %v", err)
	}
	if err := s.WithTenant(context.Background(), tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`INSERT INTO idempotency_keys
			        (tenant_id, key, status, request_binding, created_at)
			 VALUES ($1, $2, 'bound', $3, $4)`,
			tenantID, key, binding, createdAt)
		return err
	}); err != nil {
		t.Fatalf("seed bound scheduler key %s: %v", key, err)
	}
}

func marshalRotationTickReceipt(t *testing.T, receipt rotationTickReceiptFixture) []byte {
	t.Helper()
	if receipt.Runs == nil {
		receipt.Runs = []json.RawMessage{}
	}
	if receipt.Deferred == nil {
		receipt.Deferred = []json.RawMessage{}
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal scheduler tick receipt: %v", err)
	}
	return body
}

func marshalRotationTickRun(
	t *testing.T,
	scheduleID, runID string,
	dueAt time.Time,
	status string,
) json.RawMessage {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"schedule_id": scheduleID,
		"run_id":      runID,
		"due_at":      dueAt,
		"status":      status,
		"rotation": map[string]any{
			"key": "rotation/fixture", "old_ref": "version:1", "new_ref": "version:2",
			"completed": false, "queued": status == "queued", "rolled_back": false,
			"rollback_attempted": false, "rollback_failed": false,
		},
		"ran_at": dueAt.Add(time.Second), "reconciled": false,
	})
	if err != nil {
		t.Fatalf("marshal scheduler run receipt: %v", err)
	}
	return body
}

func TestSecretRotationScheduleTickSameKeyRecoveryTerminalReplayAndGCLifecycleAUD113(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	dueThrough := time.Date(2026, 8, 11, 12, 30, 0, 123000000, time.UTC)
	const (
		key        = "aud113-same-key-recovery"
		binding    = "aud113-same-key-binding"
		scheduleID = "11300000-0000-4000-8000-000000000001"
	)
	seedBoundRotationTickKey(t, s, tenantA, key, binding, dueThrough)
	schedule := store.SecretRotationSchedule{
		ID: scheduleID, TenantID: tenantA, Name: "same-key-recovery",
		Provider: "connector:ci", Key: "rotation/aud113", OldRef: "version:1",
		IntervalSeconds: 3600, Enabled: true, NextRunAt: dueThrough.Add(-time.Minute),
		CreatedAt: dueThrough.Add(-time.Hour), UpdatedAt: dueThrough.Add(-time.Minute),
	}
	seedSecretRotationSchedule(t, s, schedule)

	first, state, err := s.ClaimSecretRotationScheduleTick(
		ctx, tenantA, key, binding,
		testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
		"tick-owner-one", "child-owner-one", 2*time.Minute)
	if err != nil || state != store.SecretRotationScheduleTickAcquired || !first.DueThrough.Equal(dueThrough) ||
		first.StartScheduleID != store.ZeroUUID || first.AfterScheduleID != store.ZeroUUID {
		t.Fatalf("first tick claim=%+v state=%q err=%v", first, state, err)
	}
	// Event ID is retained audit evidence, not an effect-namespace input. The API
	// derives the same outer key from the DB-verifiable registration sequence;
	// presenting a different ID at that key must conflict with the retained tick,
	// never manufacture a sibling receiver.
	if _, _, err := s.ClaimSecretRotationScheduleTick(
		ctx, tenantA, key, binding,
		"different-registration-id-same-sequence", testRotationTenantRegistrationSequence,
		"tick-id-drift-owner", "child-id-drift-owner", 2*time.Minute,
	); !errors.Is(err, store.ErrSecretRotationScheduleTickConflict) {
		t.Fatalf("same-sequence registration-ID drift error=%v, want retained-authority conflict", err)
	}
	var receiverCount int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM secret_rotation_schedule_ticks
		  WHERE tenant_id = $1 AND idempotency_key = $2`, tenantA, key).Scan(&receiverCount); err != nil {
		t.Fatalf("count same-namespace scheduler receivers: %v", err)
	}
	if receiverCount != 1 {
		t.Fatalf("same-sequence registration-ID drift created %d receivers, want exactly one", receiverCount)
	}
	_, state, err = s.ClaimSecretRotationScheduleTick(
		ctx, tenantA, key, binding,
		testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
		"tick-live-contender", "child-live-contender", 2*time.Minute)
	if err != nil || state != store.SecretRotationScheduleTickSameKeyBusy {
		t.Fatalf("live same-key claim state=%q err=%v, want explicit busy", state, err)
	}

	schedule, err = s.GetSecretRotationScheduleTickRow(ctx, tenantA, key, 1)
	if err != nil {
		t.Fatalf("load immutable row: %v", err)
	}
	started, err := s.StartSecretRotationScheduleTickRow(
		ctx, first, first.OwnerToken, first.OwnerGeneration, schedule,
		"child-owner-one", 2*time.Minute)
	if err != nil || started.Phase != "row_started" || started.CurrentSchedule == nil {
		t.Fatalf("start durable row: tick=%+v err=%v", started, err)
	}
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE secret_rotation_schedule_scan_cursors
			    SET lease_until = clock_timestamp() - interval '1 second'
			  WHERE tenant_id = $1`, tenantA)
		return err
	}); err != nil {
		t.Fatalf("expire first aggregate lease: %v", err)
	}

	recovered, state, err := s.ClaimSecretRotationScheduleTick(
		ctx, tenantA, key, binding,
		testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
		"tick-owner-two", "child-owner-two", 2*time.Minute)
	if err != nil || state != store.SecretRotationScheduleTickAcquired || recovered.Phase != "row_started" ||
		recovered.CurrentSchedule == nil || recovered.CurrentSchedule.ID != scheduleID ||
		recovered.CurrentCommandLeaseToken != "child-owner-two" || recovered.OwnerGeneration <= started.OwnerGeneration ||
		!recovered.DueThrough.Equal(first.DueThrough) || recovered.Ran != 0 || recovered.Scanned != 0 {
		t.Fatalf("same-key recovery lost exact state: tick=%+v state=%q err=%v", recovered, state, err)
	}

	deferred := json.RawMessage(fmt.Sprintf(
		`{"schedule_id":%q,"reason":"approval_pending","due_at":%q}`,
		scheduleID, schedule.NextRunAt.Format(time.RFC3339Nano)))
	progressBody := marshalRotationTickReceipt(t, rotationTickReceiptFixture{
		Scanned: 1, Deferred: []json.RawMessage{deferred},
	})
	progressed, err := s.CompleteSecretRotationScheduleTickRow(
		ctx, recovered, recovered.OwnerToken, recovered.OwnerGeneration,
		progressBody, 0, 1, nil, 2*time.Minute)
	if err != nil || progressed.Phase != "ready" || progressed.AfterScheduleID != scheduleID ||
		progressed.CurrentSchedule != nil || progressed.Scanned != 1 {
		t.Fatalf("persist one ordered row outcome: tick=%+v err=%v", progressed, err)
	}

	terminalReceipt := rotationTickReceiptFixture{
		Scanned: 1, Deferred: []json.RawMessage{deferred}, Complete: true,
	}
	terminalBody := marshalRotationTickReceipt(t, terminalReceipt)
	terminal, err := s.FinalizeSecretRotationScheduleTick(
		ctx, progressed, progressed.OwnerToken, progressed.OwnerGeneration,
		200, terminalBody, nil)
	if err != nil || terminal.TerminalHTTPStatus == nil || *terminal.TerminalHTTPStatus != 200 ||
		!bytes.Equal(terminal.TerminalBody, terminalBody) {
		t.Fatalf("finalize exact scheduler response: tick=%+v err=%v", terminal, err)
	}
	replayed, state, err := s.ClaimSecretRotationScheduleTick(
		ctx, tenantA, key, binding,
		testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
		"unused-replay-owner", "unused-replay-child", time.Minute)
	if err != nil || state != store.SecretRotationScheduleTickTerminal ||
		!bytes.Equal(replayed.TerminalBody, terminalBody) {
		t.Fatalf("terminal same-key replay changed bytes: tick=%+v state=%q err=%v", replayed, state, err)
	}

	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE secret_rotation_schedule_ticks SET receipt = '{}'::jsonb
			  WHERE tenant_id = $1 AND idempotency_key = $2`, tenantA, key)
		return err
	}); err == nil {
		t.Fatal("trstctl_app forged protected scheduler progress")
	}
	if _, err := s.GetSecretRotationScheduleTick(ctx, tenantB, key); !store.IsNotFound(err) {
		t.Fatalf("tenant B observed tenant A scheduler tick: %v", err)
	}

	// Bound outer rows have completed_at=NULL and are never eligible for generic
	// idempotency GC, so the FK cannot erase a recoverable tick in the crash gap.
	sweeper := idemgc.New(s, time.Nanosecond)
	if deleted, err := sweeper.Sweep(ctx); err != nil || deleted != 0 {
		t.Fatalf("bound outer GC deleted=%d err=%v, want no deletion", deleted, err)
	}
	if _, err := s.GetSecretRotationScheduleTick(ctx, tenantA, key); err != nil {
		t.Fatalf("bound outer GC removed scheduler receiver: %v", err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE idempotency_keys
			    SET status = 'completed', result = $3,
			        completed_at = clock_timestamp() - interval '1 hour'
			  WHERE tenant_id = $1 AND key = $2 AND status = 'bound'`,
			tenantA, key, []byte(`{"status":200}`))
		return err
	}); err != nil {
		t.Fatalf("complete outer fixture: %v", err)
	}
	if deleted, err := sweeper.Sweep(ctx); err != nil || deleted != 1 {
		t.Fatalf("completed outer GC deleted=%d err=%v, want one", deleted, err)
	}
	if _, err := s.GetSecretRotationScheduleTick(ctx, tenantA, key); !store.IsNotFound(err) {
		t.Fatalf("completed outer GC did not cascade its tick: %v", err)
	}

	newCutoff := dueThrough.Add(time.Hour)
	seedBoundRotationTickKey(t, s, tenantA, key, "aud113-reused-binding", newCutoff)
	reused, state, err := s.ClaimSecretRotationScheduleTick(
		ctx, tenantA, key, "aud113-reused-binding",
		testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
		"tick-reused-owner", "child-reused-owner", time.Minute)
	if err != nil || state != store.SecretRotationScheduleTickAcquired || !reused.DueThrough.Equal(newCutoff) ||
		reused.StartScheduleID != scheduleID {
		t.Fatalf("post-retention raw-key reuse retained old tick authority: tick=%+v state=%q err=%v", reused, state, err)
	}
}

func TestSecretRotationScheduleTickDifferentKeySupersessionPreservesOldOuterAndCursorAUD113(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	cutoff := time.Date(2026, 8, 11, 13, 0, 0, 0, time.UTC)
	const (
		oldKey     = "aud113-expired-old"
		oldBinding = "aud113-expired-old-binding"
		newKey     = "aud113-takeover-new"
		newBinding = "aud113-takeover-new-binding"
		scheduleID = "11300000-0000-4000-8000-000000000002"
	)
	seedBoundRotationTickKey(t, s, tenantA, oldKey, oldBinding, cutoff)
	seedBoundRotationTickKey(t, s, tenantA, newKey, newBinding, cutoff.Add(time.Second))
	schedule := store.SecretRotationSchedule{
		ID: scheduleID, TenantID: tenantA, Name: "superseded-row",
		Provider: "connector:ci", Key: "rotation/superseded", OldRef: "version:1",
		IntervalSeconds: 3600, Enabled: true, NextRunAt: cutoff.Add(-time.Minute),
	}
	seedSecretRotationSchedule(t, s, schedule)
	oldTick, state, err := s.ClaimSecretRotationScheduleTick(
		ctx, tenantA, oldKey, oldBinding,
		testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
		"old-owner", "old-child", time.Minute)
	if err != nil || state != store.SecretRotationScheduleTickAcquired {
		t.Fatalf("claim old tick state=%q err=%v", state, err)
	}
	schedule, err = s.GetSecretRotationScheduleTickRow(ctx, tenantA, oldKey, 1)
	if err != nil {
		t.Fatalf("load immutable old row: %v", err)
	}
	oldTick, err = s.StartSecretRotationScheduleTickRow(
		ctx, oldTick, oldTick.OwnerToken, oldTick.OwnerGeneration,
		schedule, "old-child", time.Minute)
	if err != nil {
		t.Fatalf("start old row: %v", err)
	}
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE secret_rotation_schedule_scan_cursors
			    SET lease_until = clock_timestamp() - interval '1 second'
			  WHERE tenant_id = $1`, tenantA)
		return err
	}); err != nil {
		t.Fatalf("expire old tick: %v", err)
	}

	newTick, state, err := s.ClaimSecretRotationScheduleTick(
		ctx, tenantA, newKey, newBinding,
		testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
		"new-owner", "new-child", time.Minute)
	if err != nil || state != store.SecretRotationScheduleTickAcquired ||
		newTick.StartScheduleID != scheduleID || newTick.AfterScheduleID != store.ZeroUUID ||
		newTick.SnapshotCount == 0 {
		t.Fatalf("different-key takeover advanced old cursor: tick=%+v state=%q err=%v", newTick, state, err)
	}
	superseded, err := s.GetSecretRotationScheduleTick(ctx, tenantA, oldKey)
	if err != nil || superseded.Phase != "terminal" || superseded.TerminalHTTPStatus == nil ||
		*superseded.TerminalHTTPStatus != 503 || superseded.AfterScheduleID != store.ZeroUUID {
		t.Fatalf("old tick was not terminalized in place: %+v err=%v", superseded, err)
	}
	var receipt rotationTickReceiptFixture
	if err := json.Unmarshal(superseded.TerminalBody, &receipt); err != nil ||
		receipt.SystemError != store.SecretRotationScheduleTickSupersededError ||
		receipt.FailedScheduleID != scheduleID || receipt.Complete {
		t.Fatalf("superseded terminal receipt=%+v err=%v", receipt, err)
	}
	stableBody := append([]byte(nil), superseded.TerminalBody...)
	staleProgress := marshalRotationTickReceipt(t, rotationTickReceiptFixture{Scanned: 1})
	if _, err := s.CompleteSecretRotationScheduleTickRow(
		ctx, oldTick, oldTick.OwnerToken, oldTick.OwnerGeneration,
		staleProgress, 0, 1, nil, time.Minute); !errors.Is(err, store.ErrSecretRotationScheduleTickConflict) {
		t.Fatalf("superseded owner progress error=%v, want non-idempotency conflict", err)
	}
	var outerStatus string
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT status FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`,
			tenantA, oldKey).Scan(&outerStatus)
	}); err != nil || outerStatus != "bound" {
		t.Fatalf("stale owner deleted or changed old outer key: status=%q err=%v", outerStatus, err)
	}
	retained, err := s.GetSecretRotationScheduleTick(ctx, tenantA, oldKey)
	if err != nil || !bytes.Equal(retained.TerminalBody, stableBody) {
		t.Fatalf("stale owner changed superseded terminal bytes: tick=%+v err=%v", retained, err)
	}
	replayed, state, err := s.ClaimSecretRotationScheduleTick(
		ctx, tenantA, oldKey, oldBinding,
		testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
		"old-replay-owner", "old-replay-child", time.Minute)
	if err != nil || state != store.SecretRotationScheduleTickTerminal ||
		!bytes.Equal(replayed.TerminalBody, stableBody) {
		t.Fatalf("old key did not replay retained indeterminate bytes: tick=%+v state=%q err=%v", replayed, state, err)
	}
}

func TestSecretRotationScheduleTickReregistrationMakesPriorLifecycleInertAUD106(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	cutoff := time.Date(2026, 8, 11, 13, 30, 0, 0, time.UTC)
	const (
		oldKey     = "aud106-lifecycle-sequence-1"
		newKey     = "aud106-lifecycle-sequence-2"
		oldBinding = "aud106-binding-sequence-1"
		newBinding = "aud106-binding-sequence-2"
		scheduleID = "10600000-0000-4000-8000-000000000106"
	)
	seedBoundRotationTickKey(t, s, tenantA, oldKey, oldBinding, cutoff)
	seedBoundRotationTickKey(t, s, tenantA, newKey, newBinding, cutoff)
	seedSecretRotationSchedule(t, s, store.SecretRotationSchedule{
		ID: scheduleID, TenantID: tenantA, Name: "lifecycle-one",
		Provider: "connector:ci", Key: "rotation/same", OldRef: "version:1",
		IntervalSeconds: 3600, Enabled: true, NextRunAt: cutoff.Add(-time.Minute),
	})
	oldTick, state, err := s.ClaimSecretRotationScheduleTick(
		ctx, tenantA, oldKey, oldBinding,
		testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
		"old-lifecycle-owner", "old-lifecycle-child", time.Minute)
	if err != nil || state != store.SecretRotationScheduleTickAcquired || oldTick.SnapshotCount != 1 {
		t.Fatalf("claim first lifecycle tick=%+v state=%q err=%v", oldTick, state, err)
	}
	oldRow, err := s.GetSecretRotationScheduleTickRow(ctx, tenantA, oldKey, 1)
	if err != nil {
		t.Fatalf("load first lifecycle snapshot: %v", err)
	}

	const newRegistrationSequence = uint64(2)
	const newRegistrationID = "legacy-registration-id-without-modern-prefix"
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE tenants SET event_seq = $2 WHERE tenant_id = $1`,
		tenantA, newRegistrationSequence); err != nil {
		t.Fatalf("advance live tenant registration: %v", err)
	}
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretRotationScheduleUpsertedTx(ctx, tx, store.SecretRotationSchedule{
			ID: scheduleID, TenantID: tenantA, Name: "lifecycle-two",
			Provider: "connector:ci", Key: "rotation/same", OldRef: "version:1",
			IntervalSeconds: 3600, ConfigEventSequence: 3,
			Enabled: true, NextRunAt: cutoff.Add(-time.Minute),
		})
	}); err != nil {
		t.Fatalf("project same schedule into second lifecycle: %v", err)
	}

	newTick, state, err := s.ClaimSecretRotationScheduleTick(
		ctx, tenantA, newKey, newBinding, newRegistrationID, newRegistrationSequence,
		"new-lifecycle-owner", "new-lifecycle-child", time.Minute)
	if err != nil || state != store.SecretRotationScheduleTickAcquired ||
		newTick.SnapshotCount != 1 || newTick.TenantRegistrationEventID != newRegistrationID ||
		newTick.TenantRegistrationEventSequence != newRegistrationSequence {
		t.Fatalf("claim second lifecycle tick=%+v state=%q err=%v", newTick, state, err)
	}
	if _, err := s.StartSecretRotationScheduleTickRow(
		ctx, oldTick, oldTick.OwnerToken, oldTick.OwnerGeneration,
		oldRow, "stale-old-child", time.Minute,
	); !errors.Is(err, store.ErrSecretRotationScheduleTickConflict) {
		t.Fatalf("prior lifecycle resumed after re-registration: %v", err)
	}
	var receiverCount int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM secret_rotation_schedule_ticks WHERE tenant_id = $1`, tenantA).
		Scan(&receiverCount); err != nil {
		t.Fatalf("count lifecycle-scoped scheduler receivers: %v", err)
	}
	if receiverCount != 2 {
		t.Fatalf("re-registration retained %d scheduler receivers, want old evidence plus new authority", receiverCount)
	}
}

func TestSecretRotationScheduleTickRecoveredBudgetCannotExceedBoundsAUD113(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	cutoff := time.Date(2026, 8, 11, 14, 0, 0, 0, time.UTC)
	const (
		key        = "aud113-budget-resume"
		binding    = "aud113-budget-binding"
		previousID = "11300000-0000-4000-8000-000000000003"
		currentID  = "11300000-0000-4000-8000-000000000004"
	)
	seedBoundRotationTickKey(t, s, tenantA, key, binding, cutoff)
	runs := make([]json.RawMessage, 0, 50)
	for index := 0; index < 49; index++ {
		scheduleID := fmt.Sprintf("11310000-0000-4000-8000-%012d", index+1)
		runID := fmt.Sprintf("11320000-0000-4000-8000-%012d", index+1)
		runs = append(runs, marshalRotationTickRun(
			t, scheduleID, runID, cutoff.Add(-time.Duration(index+2)*time.Minute), "queued"))
	}
	progress := rotationTickReceiptFixture{Ran: 49, Scanned: 499, Runs: runs}
	progressBody := marshalRotationTickReceipt(t, progress)
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO secret_rotation_schedule_scan_cursors
			        (tenant_id, after_schedule_id, active_tick_key,
			         active_tick_binding, lease_token, lease_until,
			         lease_generation, generation, updated_at)
			 VALUES ($1, $2, $3, $4, 'expired-owner',
			         clock_timestamp() - interval '1 second', 1, 499, clock_timestamp())`,
			tenantA, previousID, key, binding); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO secret_rotation_schedule_ticks
			        (tenant_id, identity_version, tenant_registration_event_id,
			         tenant_registration_event_sequence,
			         idempotency_key, request_binding, due_through,
			         start_schedule_id, after_schedule_id, phase,
			         current_schedule_id, current_due_at, current_provider,
			         current_secret_key, current_old_ref, current_interval_seconds,
			         current_config_event_sequence, current_command_lease_token,
			         ran, scanned, snapshot_count, receipt,
			         owner_token, owner_generation, created_at, updated_at)
			 VALUES ($1, 3, $2, $3, $4, $5, $6, $7, $7, 'row_started',
			         $8, $9, 'connector:ci', 'rotation/budget', 'version:1', 3600,
			         2, 'expired-child', 49, 499, 500, $10::jsonb,
			         'expired-owner', 1, $6, $6)`,
			tenantA, testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
			key, binding, cutoff, previousID, currentID,
			cutoff.Add(-time.Minute), progressBody)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO secret_rotation_schedule_tick_rows
			        (tenant_id, identity_version, tenant_registration_event_id,
			         tenant_registration_event_sequence,
			         idempotency_key, ordinal, schedule_id, due_at,
			         provider, secret_key, old_ref, interval_seconds, config_event_sequence)
			 SELECT $1, 3, $2, $3, $4, ordinal,
			        ('00000000-0000-4000-8000-' || lpad(ordinal::text, 12, '0'))::uuid,
			        $5, 'connector:ci', 'rotation/fixture', 'version:1', 3600, 2
			   FROM generate_series(1, 499) AS ordinal`,
			tenantA, testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
			key, cutoff.Add(-time.Hour)); err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO secret_rotation_schedule_tick_rows
			        (tenant_id, identity_version, tenant_registration_event_id,
			         tenant_registration_event_sequence,
			         idempotency_key, ordinal, schedule_id, due_at,
			         provider, secret_key, old_ref, interval_seconds, config_event_sequence)
			 VALUES ($1, 3, $2, $3, $4, 500, $5, $6,
			         'connector:ci', 'rotation/budget', 'version:1', 3600, 2)`,
			tenantA, testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
			key, currentID, cutoff.Add(-time.Minute))
		return err
	}); err != nil {
		t.Fatalf("seed crash-at-49/499 tick: %v", err)
	}

	recovered, state, err := s.ClaimSecretRotationScheduleTick(
		ctx, tenantA, key, binding,
		testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
		"budget-owner", "budget-child", time.Minute)
	if err != nil || state != store.SecretRotationScheduleTickAcquired ||
		recovered.Ran != 49 || recovered.Scanned != 499 || recovered.CurrentSchedule == nil {
		t.Fatalf("recover 49/499 tick=%+v state=%q err=%v", recovered, state, err)
	}
	progress.Ran = 50
	progress.Scanned = 500
	progress.Runs = append(progress.Runs, marshalRotationTickRun(
		t, currentID,
		orchestrator.SecretRotationScheduleRunID(
			tenantA, testRotationTenantRegistrationSequence, currentID, cutoff.Add(-time.Minute)),
		cutoff.Add(-time.Minute), "queued"))
	boundedBody := marshalRotationTickReceipt(t, progress)
	bounded, err := s.CompleteSecretRotationScheduleTickRow(
		ctx, recovered, recovered.OwnerToken, recovered.OwnerGeneration,
		boundedBody, 50, 500, nil, time.Minute)
	if err != nil || bounded.Ran != 50 || bounded.Scanned != 500 {
		t.Fatalf("resume to exact logical bounds: tick=%+v err=%v", bounded, err)
	}
	if _, err := s.StartSecretRotationScheduleTickRow(
		ctx, bounded, bounded.OwnerToken, bounded.OwnerGeneration,
		store.SecretRotationSchedule{
			ID: "11300000-0000-4000-8000-000000000005", TenantID: tenantA,
			Provider: "connector:ci", Key: "rotation/too-many", OldRef: "version:1",
			IntervalSeconds: 3600, Enabled: true, NextRunAt: cutoff.Add(-time.Second),
		}, "too-many-child", time.Minute); !errors.Is(err, store.ErrSecretRotationScheduleTickConflict) {
		t.Fatalf("tick exceeded 50/500 after recovery: %v", err)
	}
	progress.RunLimitReached = true
	progress.ScanLimitReached = true
	terminalBody := marshalRotationTickReceipt(t, progress)
	if _, err := s.FinalizeSecretRotationScheduleTick(
		ctx, bounded, bounded.OwnerToken, bounded.OwnerGeneration,
		200, terminalBody, nil); err != nil {
		t.Fatalf("finalize conservative exact-bound receipt: %v", err)
	}
}

func TestSecretRotationScheduleTickImmutableSnapshotVisitsRingOnceAUD113(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	cutoff := time.Date(2026, 8, 11, 15, 0, 0, 0, time.UTC)
	const (
		key     = "aud113-wrap-restart"
		binding = "aud113-wrap-restart-binding"
		lowID   = "11300000-0000-4000-8000-000000000010"
		startID = "11300000-0000-4000-8000-000000000020"
		highID  = "11300000-0000-4000-8000-000000000030"
	)
	seedBoundRotationTickKey(t, s, tenantA, key, binding, cutoff)
	for index, id := range []string{lowID, startID, highID} {
		seedSecretRotationSchedule(t, s, store.SecretRotationSchedule{
			ID: id, TenantID: tenantA, Name: fmt.Sprintf("wrap-%d", index),
			Provider: "connector:ci", Key: fmt.Sprintf("rotation/wrap-%d", index),
			OldRef: "version:1", IntervalSeconds: 3600, Enabled: true,
			NextRunAt: cutoff.Add(-time.Minute),
		})
	}
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO secret_rotation_schedule_scan_cursors
			        (tenant_id, after_schedule_id, generation, updated_at)
			 VALUES ($1, $2, 7, clock_timestamp())`, tenantA, startID)
		return err
	}); err != nil {
		t.Fatalf("seed midpoint ring cursor: %v", err)
	}
	tick, state, err := s.ClaimSecretRotationScheduleTick(
		ctx, tenantA, key, binding,
		testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
		"wrap-owner-one", "wrap-child-one", time.Minute)
	if err != nil || state != store.SecretRotationScheduleTickAcquired ||
		tick.StartScheduleID != startID || tick.AfterScheduleID != startID || tick.SnapshotCount != 3 {
		t.Fatalf("claim midpoint ring tick=%+v state=%q err=%v", tick, state, err)
	}

	// Mutating the live projection after the outer bind cannot change the exact
	// frozen membership or tuple used by this retryable tick.
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE secret_rotation_schedules
			    SET provider = 'connector:changed', config_event_sequence = 3
			  WHERE tenant_id = $1 AND id = $2`, tenantA, lowID)
		return err
	}); err != nil {
		t.Fatalf("mutate live schedule after snapshot: %v", err)
	}

	wantOrder := []string{highID, lowID, startID}
	visited := make([]string, 0, len(wantOrder))
	for ordinal, wantID := range wantOrder {
		schedule, err := s.GetSecretRotationScheduleTickRow(ctx, tenantA, key, ordinal+1)
		if err != nil || schedule.ID != wantID {
			t.Fatalf("immutable ordinal %d = %+v err=%v, want %s", ordinal+1, schedule, err, wantID)
		}
		if wantID == lowID && (schedule.Provider != "connector:ci" || schedule.ConfigEventSequence != 2) {
			t.Fatalf("live projection mutation changed frozen low row: %+v", schedule)
		}
		childToken := "wrap-child-" + schedule.ID
		tick, err = s.StartSecretRotationScheduleTickRow(
			ctx, tick, tick.OwnerToken, tick.OwnerGeneration, schedule, childToken, time.Minute)
		if err != nil {
			t.Fatalf("start immutable row %s: %v", schedule.ID, err)
		}
		visited = append(visited, schedule.ID)
		tick, err = s.CompleteSecretRotationScheduleTickRow(
			ctx, tick, tick.OwnerToken, tick.OwnerGeneration,
			marshalRotationTickReceipt(t, rotationTickReceiptFixture{Scanned: len(visited)}),
			0, len(visited), nil, time.Minute)
		if err != nil {
			t.Fatalf("complete immutable row %s: %v", schedule.ID, err)
		}
	}
	if fmt.Sprint(visited) != fmt.Sprint(wantOrder) {
		t.Fatalf("snapshot visit order=%v, want %v", visited, wantOrder)
	}
	if tick.Scanned != tick.SnapshotCount || tick.AfterScheduleID != startID {
		t.Fatalf("immutable snapshot did not finish exactly once: %+v", tick)
	}
}

func TestSecretRotationScheduleTickSnapshotRetainsUnanchoredRevisionForExplicitDeferralAUD112(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	cutoff := time.Date(2026, 8, 11, 15, 30, 0, 0, time.UTC)
	const (
		key        = "aud112-unanchored-config"
		binding    = "aud112-unanchored-config-binding"
		scheduleID = "11200000-0000-4000-8000-000000000001"
	)
	seedBoundRotationTickKey(t, s, tenantA, key, binding, cutoff)
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretRotationScheduleUpsertedTx(ctx, tx, store.SecretRotationSchedule{
			ID: scheduleID, TenantID: tenantA, Name: "pre-revision schedule",
			Provider: "connector:ci", Key: "rotation/unanchored", OldRef: "version:1",
			IntervalSeconds: 3600, ConfigEventSequence: 0,
			Enabled: true, NextRunAt: cutoff.Add(-time.Minute),
		})
	}); err != nil {
		t.Fatalf("seed revision-zero schedule: %v", err)
	}
	tick, state, err := s.ClaimSecretRotationScheduleTick(
		ctx, tenantA, key, binding,
		testRotationTenantRegistrationID, testRotationTenantRegistrationSequence,
		"unanchored-owner", "unanchored-child", time.Minute)
	if err != nil || state != store.SecretRotationScheduleTickAcquired || tick.SnapshotCount != 1 {
		t.Fatalf("claim revision-zero snapshot tick=%+v state=%q err=%v", tick, state, err)
	}
	row, err := s.GetSecretRotationScheduleTickRow(ctx, tenantA, key, 1)
	if err != nil || row.ID != scheduleID || row.ConfigEventSequence != 0 {
		t.Fatalf("revision-zero row was skipped or invented authority: row=%+v err=%v", row, err)
	}
	var commandCount int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM secret_rotation_schedule_commands
		  WHERE tenant_id = $1 AND tick_idempotency_key = $2`, tenantA, key).Scan(&commandCount); err != nil {
		t.Fatalf("count unanchored child commands: %v", err)
	}
	if commandCount != 0 {
		t.Fatalf("snapshotting unanchored revision created %d child commands, want zero", commandCount)
	}
}

func TestSecretRotationScheduleCommandLeaseUsesPostgresClockAndExactAggregateTokenAUD113(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	dueAt := time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)
	const scheduleID = "11300000-0000-4000-8000-000000000006"
	seedSecretRotationSchedule(t, s, store.SecretRotationSchedule{
		ID: scheduleID, TenantID: tenantA, Name: "database-clock",
		Provider: "connector:ci", Key: "rotation/clock", OldRef: "version:1",
		IntervalSeconds: 3600, Enabled: true, NextRunAt: dueAt,
	})
	command := claimScheduleCommandForTest(t, s, tenantA, scheduleID,
		"connector:ci", "rotation/clock", "version:1", dueAt, "clock")
	runID := command.RunID
	const aggregateToken = "lease-clock"
	claimed, acquired, err := s.ClaimSecretRotationScheduleCommand(
		ctx, command, aggregateToken, 30*time.Second)
	if err != nil || !acquired || claimed.LeaseToken != aggregateToken {
		t.Fatalf("first DB-clock claim=%+v acquired=%t err=%v", claimed, acquired, err)
	}
	var boundedByDatabaseClock bool
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT lease_until > clock_timestamp() + interval '20 seconds'
			        AND lease_until < clock_timestamp() + interval '40 seconds'
			   FROM secret_rotation_schedule_commands
			  WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3`,
			tenantA, scheduleID, runID).Scan(&boundedByDatabaseClock)
	}); err != nil || !boundedByDatabaseClock {
		t.Fatalf("command lease was not bounded by PostgreSQL clock: ok=%t err=%v", boundedByDatabaseClock, err)
	}
	if contender, acquired, err := s.ClaimSecretRotationScheduleCommand(
		ctx, command, "other-aggregate-token", 30*time.Second); !errors.Is(err, store.ErrSecretRotationScheduleCommandConflict) || acquired {
		t.Fatalf("other aggregate token claim=%+v acquired=%t err=%v, want conflict", contender, acquired, err)
	}
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE secret_rotation_schedule_commands
			    SET lease_until = clock_timestamp() - interval '1 second'
			  WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3`,
			tenantA, scheduleID, runID)
		return err
	}); err != nil {
		t.Fatalf("expire command fixture lease: %v", err)
	}
	takenOver, acquired, err := s.ClaimSecretRotationScheduleCommand(
		ctx, command, aggregateToken, 30*time.Second)
	if err != nil || !acquired || takenOver.LeaseToken != aggregateToken {
		t.Fatalf("expired command lease takeover=%+v acquired=%t err=%v", takenOver, acquired, err)
	}
}
