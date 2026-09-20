// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestSecretRotationCommandGCPreservesRebuildFenceAndSuccessorProgress(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	projector := projections.New(st)
	tenantEvent, err := log.Append(ctx, events.Event{
		ID: events.NewID(), Type: projections.EventTenantRegistered,
		TenantID: tenantA, Data: tenantRegisteredJSON("scheduler-gc"),
	})
	if err != nil {
		t.Fatalf("append tenant: %v", err)
	}
	if err := projector.Apply(ctx, tenantEvent); err != nil {
		t.Fatalf("project tenant: %v", err)
	}

	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	const scheduleID = "10610610-6106-4106-8106-106106106106"
	firstDue := time.Now().UTC().Truncate(time.Microsecond).Add(-2 * time.Minute)
	schedule, err := orch.UpsertSecretRotationSchedule(ctx, tenantA, store.SecretRotationSchedule{
		ID: scheduleID, Name: "bounded-command-history", Provider: "connector:ci",
		Key: "rotation/gc", OldRef: "version:1", IntervalSeconds: 60,
		Enabled: true, NextRunAt: firstDue,
	})
	if err != nil {
		t.Fatalf("upsert schedule: %v", err)
	}
	authorityCtx := events.ContextWithActor(ctx, events.Actor{Subject: "secret-rotation-schedule:" + scheduleID})
	activeTicks := map[string]store.SecretRotationScheduleTick{}
	tickNumber := 0

	claim := func(dueAt time.Time, oldRef string) store.SecretRotationScheduleCommand {
		t.Helper()
		tickNumber++
		tickKey := fmt.Sprintf("scheduler-gc-tick-%d", tickNumber)
		tickBinding := fmt.Sprintf("scheduler-gc-binding-%d", tickNumber)
		ownerToken := fmt.Sprintf("scheduler-gc-owner-%d", tickNumber)
		leaseToken := fmt.Sprintf("scheduler-gc-child-%d", tickNumber)
		tick, state, err := st.ClaimSecretRotationScheduleTick(
			ctx, tenantA, tickKey, tickBinding, tenantEvent.ID, tenantEvent.Sequence,
			ownerToken, leaseToken, time.Minute)
		if err != nil || state != store.SecretRotationScheduleTickAcquired || tick.SnapshotCount != 1 {
			t.Fatalf("claim aggregate tick %d: tick=%+v state=%q err=%v", tickNumber, tick, state, err)
		}
		row, err := st.GetSecretRotationScheduleTickRow(ctx, tenantA, tickKey, 1)
		if err != nil || row.ID != scheduleID || !row.NextRunAt.Equal(dueAt) {
			t.Fatalf("load exact due row %d: row=%+v err=%v", tickNumber, row, err)
		}
		tick, err = st.StartSecretRotationScheduleTickRow(
			ctx, tick, tick.OwnerToken, tick.OwnerGeneration, row, leaseToken, time.Minute)
		if err != nil {
			t.Fatalf("start aggregate row %d: %v", tickNumber, err)
		}
		runID := orchestrator.SecretRotationScheduleRunID(
			tenantA, tenantEvent.Sequence, scheduleID, dueAt)
		command := store.SecretRotationScheduleCommand{
			TenantID: tenantA, IdentityVersion: store.SecretRotationScheduleIdentityVersion,
			TenantRegistrationEventID:       tenantEvent.ID,
			TenantRegistrationEventSequence: tenantEvent.Sequence,
			ScheduleID:                      scheduleID, RunID: runID, DueAt: dueAt,
			Provider: "connector:ci", Key: "rotation/gc", OldRef: oldRef,
			IntervalSeconds: row.IntervalSeconds, ConfigEventSequence: row.ConfigEventSequence,
			TickIdempotencyKey: tickKey, TickOrdinal: 1,
			CommandKey:      orchestrator.SecretRotationScheduleCommandKey(runID),
			RequestBinding:  "binding-" + runID,
			TerminalEventID: orchestrator.SecretRotationScheduleRunEventID(runID),
		}
		got, acquired, err := st.ClaimSecretRotationScheduleCommand(ctx, command, leaseToken, time.Minute)
		if err != nil || !acquired {
			t.Fatalf("claim %s: got=%+v acquired=%t err=%v", runID, got, acquired, err)
		}
		activeTicks[runID] = tick
		return got
	}
	record := func(command store.SecretRotationScheduleCommand, newRef string, eventTime time.Time) store.SecretRotationScheduleRun {
		t.Helper()
		run, err := orch.RecordSecretRotationScheduleRun(authorityCtx, tenantA, store.SecretRotationScheduleRun{
			ScheduleID: scheduleID, RunID: command.RunID, Status: "queued", NewRef: newRef, RanAt: eventTime,
			TickIdempotencyKey: command.TickIdempotencyKey, TickOrdinal: command.TickOrdinal,
			LeaseToken: command.LeaseToken,
		})
		if err != nil {
			t.Fatalf("record %s: %v", command.RunID, err)
		}
		tick, ok := activeTicks[command.RunID]
		if !ok {
			t.Fatalf("missing aggregate tick for %s", command.RunID)
		}
		runReceipt, err := json.Marshal(map[string]any{
			"schedule_id": run.ScheduleID, "run_id": run.RunID, "due_at": run.DueAt,
			"status": run.Status, "rotation": map[string]any{
				"key": command.Key, "old_ref": command.OldRef, "new_ref": newRef,
				"completed": false, "queued": true, "rolled_back": false,
				"rollback_attempted": false, "rollback_failed": false,
			}, "ran_at": run.RanAt, "reconciled": false,
		})
		if err != nil {
			t.Fatalf("marshal run receipt %s: %v", command.RunID, err)
		}
		progress, err := json.Marshal(map[string]any{
			"ran": 1, "scanned": 1, "runs": []json.RawMessage{runReceipt},
			"deferred": []json.RawMessage{}, "run_limit_reached": false,
			"scan_limit_reached": false, "complete": false, "partial": false,
		})
		if err != nil {
			t.Fatalf("marshal tick progress %s: %v", command.RunID, err)
		}
		tick, err = st.CompleteSecretRotationScheduleTickRow(
			ctx, tick, tick.OwnerToken, tick.OwnerGeneration, progress, 1, 1, nil, time.Minute)
		if err != nil {
			t.Fatalf("complete aggregate row %s: %v", command.RunID, err)
		}
		terminal, err := json.Marshal(map[string]any{
			"ran": 1, "scanned": 1, "runs": []json.RawMessage{runReceipt},
			"deferred": []json.RawMessage{}, "run_limit_reached": false,
			"scan_limit_reached": false, "complete": true, "partial": false,
		})
		if err != nil {
			t.Fatalf("marshal terminal tick %s: %v", command.RunID, err)
		}
		if _, err := st.FinalizeSecretRotationScheduleTick(
			ctx, tick, tick.OwnerToken, tick.OwnerGeneration, 200, terminal, nil); err != nil {
			t.Fatalf("finalize aggregate tick %s: %v", command.RunID, err)
		}
		delete(activeTicks, command.RunID)
		return run
	}

	// Replica clocks deliberately move backward across append order. Cadence must
	// follow due_at, not either producer's wall clock.
	firstEventTime := time.Date(2026, 8, 11, 22, 0, 0, 0, time.UTC)
	secondEventTime := firstEventTime.Add(-2 * time.Hour)
	firstCommand := claim(firstDue, "version:1")
	firstRun := record(firstCommand, "version:2", firstEventTime)
	afterFirst, err := st.GetSecretRotationSchedule(ctx, tenantA, schedule.ID)
	wantSecondDue := firstDue.Add(time.Minute)
	if err != nil || !afterFirst.NextRunAt.Equal(wantSecondDue) {
		t.Fatalf("first successor edge=%+v err=%v, want due_at cadence %s", afterFirst, err, wantSecondDue)
	}
	secondCommand := claim(afterFirst.NextRunAt, "version:2")
	secondRun := record(secondCommand, "version:3", secondEventTime)
	afterSecond, err := st.GetSecretRotationSchedule(ctx, tenantA, schedule.ID)
	wantThirdDue := wantSecondDue.Add(time.Minute)
	if err != nil || !afterSecond.NextRunAt.Equal(wantThirdDue) || afterSecond.LastRunAt == nil ||
		!afterSecond.LastRunAt.Equal(secondEventTime) {
		t.Fatalf("clock-skewed successor edge=%+v err=%v, want due=%s event_time=%s",
			afterSecond, err, wantThirdDue, secondEventTime)
	}

	purged, err := orch.PurgeSecretRotationScheduleCommands(ctx, tenantA, 10)
	if err != nil || purged != 1 {
		t.Fatalf("bounded command purge=%d err=%v, want exactly the older terminal row", purged, err)
	}
	if _, err := st.GetSecretRotationScheduleCommand(ctx, tenantA, scheduleID, firstCommand.RunID); !store.IsNotFound(err) {
		t.Fatalf("old command survived verified purge: %v", err)
	}
	latest, err := st.GetSecretRotationScheduleCommand(ctx, tenantA, scheduleID, secondCommand.RunID)
	if err != nil || latest.Status != "queued" {
		t.Fatalf("newest finite lineage fence=%+v err=%v", latest, err)
	}

	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("full event rebuild after command purge: %v", err)
	}
	rebuilt, err := st.GetSecretRotationSchedule(ctx, tenantA, scheduleID)
	if err != nil || rebuilt.OldRef != "version:3" || rebuilt.LastRunID == nil ||
		*rebuilt.LastRunID != secondRun.RunID || !rebuilt.NextRunAt.Equal(afterSecond.NextRunAt) {
		t.Fatalf("rebuilt successor regressed or recreated old edge: %+v err=%v", rebuilt, err)
	}
	if _, err := st.GetSecretRotationScheduleCommand(ctx, tenantA, scheduleID, firstCommand.RunID); !store.IsNotFound(err) {
		t.Fatalf("read-model rebuild recreated GC'd command: %v", err)
	}

	// Once verified GC removes the constant-time SQL authority, direct recovery
	// fails closed. It must not fall back to a tenant-wide EventByID scan, even
	// though the immutable event remains available for a full ordered rebuild.
	if got, found, err := orch.ReconcileSecretRotationScheduleRun(
		authorityCtx, tenantA, scheduleID, firstRun.RunID, firstDue); err == nil || found {
		t.Fatalf("reconcile GC'd old edge: got=%+v found=%t err=%v, want fail-closed missing authority", got, found, err)
	}
	afterOldReconcile, err := st.GetSecretRotationSchedule(ctx, tenantA, scheduleID)
	if err != nil || afterOldReconcile.OldRef != rebuilt.OldRef ||
		!afterOldReconcile.NextRunAt.Equal(rebuilt.NextRunAt) {
		t.Fatalf("old retained event regressed rebuilt successor: %+v err=%v", afterOldReconcile, err)
	}

	thirdCommand := claim(rebuilt.NextRunAt, "version:3")
	thirdRun := record(thirdCommand, "version:4", secondEventTime.Add(-2*time.Hour))
	afterThird, err := st.GetSecretRotationSchedule(ctx, tenantA, scheduleID)
	if err != nil || afterThird.OldRef != "version:4" || afterThird.LastRunID == nil ||
		*afterThird.LastRunID != thirdRun.RunID || !afterThird.NextRunAt.Equal(wantThirdDue.Add(time.Minute)) {
		t.Fatalf("current successor did not progress after rebuild: %+v err=%v", afterThird, err)
	}
	purged, err = orch.PurgeSecretRotationScheduleCommands(ctx, tenantA, 10)
	if err != nil || purged != 1 {
		t.Fatalf("second bounded command purge=%d err=%v", purged, err)
	}
	var retained int
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM secret_rotation_schedule_commands
			  WHERE tenant_id = $1 AND schedule_id = $2`, tenantA, scheduleID).Scan(&retained)
	}); err != nil || retained != 1 {
		t.Fatalf("steady-state command rows=%d err=%v, want one newest fence", retained, err)
	}
}
