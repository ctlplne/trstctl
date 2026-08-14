// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	cryptoboundary "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/rotationcommand"
	"trstctl.com/trstctl/internal/store"
)

// SecretRotationScheduleRunID is the stable UUID for one exact tenant schedule
// due edge. It is independent of whichever authorized HTTP runner happens to
// notice the row, so failover cannot mint another command identity.
func SecretRotationScheduleRunID(tenantID string, tenantRegistrationEventSequence uint64, scheduleID string, dueAt time.Time) string {
	return rotationcommand.RunID(tenantID, tenantRegistrationEventSequence, scheduleID, dueAt)
}

// SecretRotationScheduleCommandKey is the inner AN-5 identity shared by the
// schedule command and the application-secret event/outbox receiver.
func SecretRotationScheduleCommandKey(runID string) string {
	return rotationcommand.CommandKey(runID)
}

// SecretRotationScheduleRunEventID is the retained immutable terminal receipt
// identity for a deterministic run.
func SecretRotationScheduleRunEventID(runID string) string {
	return rotationcommand.TerminalEventID(runID)
}

// UpsertSecretRotationSchedule records a tenant rotation cadence as an immutable
// event. The served API admits connector-backed cadences only; replay still
// accepts historical static rows so the scheduler can disable them truthfully.
// The relational schedule row is a projection.
func (o *Orchestrator) UpsertSecretRotationSchedule(ctx context.Context, tenantID string, in store.SecretRotationSchedule) (store.SecretRotationSchedule, error) {
	id := in.ID
	if id == "" {
		id = uuid.NewString()
	}
	payload, err := json.Marshal(projections.SecretRotationScheduleUpserted{
		ID: id, Name: strings.TrimSpace(in.Name), Provider: strings.TrimSpace(in.Provider),
		Key: strings.TrimSpace(in.Key), OldRef: strings.TrimSpace(in.OldRef),
		IntervalSeconds: in.IntervalSeconds, Enabled: in.Enabled, NextRunAt: in.NextRunAt,
	})
	if err != nil {
		return store.SecretRotationSchedule{}, err
	}
	ev, err := o.emit(ctx, projections.EventSecretRotationScheduleUpserted, tenantID, payload)
	if err != nil {
		return store.SecretRotationSchedule{}, err
	}
	nextRunAt := in.NextRunAt
	if nextRunAt.IsZero() {
		nextRunAt = ev.Time.Add(time.Duration(in.IntervalSeconds) * time.Second)
	}
	return store.SecretRotationSchedule{
		ID: id, TenantID: tenantID, Name: strings.TrimSpace(in.Name),
		Provider: strings.TrimSpace(in.Provider), Key: strings.TrimSpace(in.Key),
		OldRef: strings.TrimSpace(in.OldRef), IntervalSeconds: in.IntervalSeconds,
		ConfigEventSequence: ev.Sequence, Enabled: in.Enabled, NextRunAt: nextRunAt,
		CreatedAt: ev.Time, UpdatedAt: ev.Time,
	}, nil
}

// RecordSecretRotationScheduleRun records the outcome of one due scheduled
// rotation. It stores metadata and refs only; credential values stay inside the
// configured rotator/provider.
func (o *Orchestrator) RecordSecretRotationScheduleRun(ctx context.Context, tenantID string, in store.SecretRotationScheduleRun) (store.SecretRotationScheduleRun, error) {
	if in.RunID == "" {
		return store.SecretRotationScheduleRun{}, errors.New("orchestrator: scheduled rotation terminal run requires deterministic run id")
	}
	command, err := o.store.GetSecretRotationScheduleCommand(ctx, tenantID, in.ScheduleID, in.RunID)
	if err != nil {
		return store.SecretRotationScheduleRun{}, fmt.Errorf("orchestrator: load scheduled rotation command authority: %w", err)
	}
	wantEventID := SecretRotationScheduleRunEventID(in.RunID)
	if command.TerminalEventID != wantEventID ||
		command.IdentityVersion != store.SecretRotationScheduleIdentityVersion ||
		!rotationcommand.Matches(tenantID, command.TenantRegistrationEventSequence,
			in.ScheduleID, in.RunID, command.DueAt, command.CommandKey, wantEventID) {
		return store.SecretRotationScheduleRun{}, fmt.Errorf("%w: scheduled rotation terminal event identity differs", store.ErrSecretRotationScheduleCommandConflict)
	}
	if !secretRotationScheduleTerminalStatus(in.Status) {
		return store.SecretRotationScheduleRun{}, fmt.Errorf(
			"%w: status %q is not terminal", store.ErrSecretRotationScheduleCommandConflict, in.Status)
	}
	wantActor := "secret-rotation-schedule:" + in.ScheduleID
	actor, ok := events.ActorFromContext(ctx)
	if !ok || actor.Subject != wantActor {
		return store.SecretRotationScheduleRun{}, fmt.Errorf(
			"%w: scheduled rotation terminal actor differs", store.ErrSecretRotationScheduleCommandConflict)
	}
	payload, err := json.Marshal(projections.SecretRotationScheduleRan{
		ScheduleID: in.ScheduleID, RunID: in.RunID, DueAt: command.DueAt,
		TenantRegistrationEventID:       command.TenantRegistrationEventID,
		TenantRegistrationEventSequence: command.TenantRegistrationEventSequence,
		Provider:                        command.Provider, Key: command.Key, OldRef: command.OldRef,
		IntervalSeconds: command.IntervalSeconds, ConfigEventSequence: command.ConfigEventSequence,
		CommandKey: command.CommandKey, RequestBinding: command.RequestBinding,
		Status: in.Status, NewRef: in.NewRef, Error: in.Error,
	})
	if err != nil {
		return store.SecretRotationScheduleRun{}, err
	}
	preparedRun := store.SecretRotationScheduleRun{
		TenantID: tenantID, IdentityVersion: command.IdentityVersion,
		TenantRegistrationEventID:       command.TenantRegistrationEventID,
		TenantRegistrationEventSequence: command.TenantRegistrationEventSequence,
		ScheduleID:                      in.ScheduleID, RunID: in.RunID,
		SchemaVersion: projections.SecretRotationScheduleRanEventSchemaVersion,
		DueAt:         command.DueAt, Provider: command.Provider, Key: command.Key, OldRef: command.OldRef,
		IntervalSeconds: command.IntervalSeconds, ConfigEventSequence: command.ConfigEventSequence,
		CommandKey: command.CommandKey, RequestBinding: command.RequestBinding,
		Status: in.Status, NewRef: in.NewRef, Error: in.Error, RanAt: in.RanAt,
		EventID: wantEventID, EventType: projections.EventSecretRotationScheduleRan,
		EventDigest:        cryptoboundary.SHA256Hex(payload),
		TickIdempotencyKey: in.TickIdempotencyKey, TickOrdinal: in.TickOrdinal,
		LeaseToken: in.LeaseToken,
	}
	preparedCommand, err := o.store.PrepareSecretRotationScheduleCommandTerminal(ctx, preparedRun)
	if err != nil {
		return store.SecretRotationScheduleRun{}, fmt.Errorf("orchestrator: prepare scheduled rotation terminal intent: %w", err)
	}
	if preparedCommand.PreparedAt == nil {
		return store.SecretRotationScheduleRun{}, fmt.Errorf(
			"%w: prepared scheduled rotation command has no event time", store.ErrSecretRotationScheduleCommandConflict)
	}
	if preparedCommand.Status != "claimed" {
		retained, found, reconcileErr := o.reconcileSecretRotationScheduleRun(
			ctx, tenantID, in.ScheduleID, in.RunID, wantEventID, time.Time{})
		if reconcileErr != nil {
			return store.SecretRotationScheduleRun{}, reconcileErr
		}
		if !found {
			return store.SecretRotationScheduleRun{}, fmt.Errorf(
				"%w: terminal SQL receipt has no retained event", store.ErrSecretRotationScheduleCommandConflict)
		}
		return retained, nil
	}
	ev, err := o.emitPreparedSecretRotationScheduleRun(ctx, events.Event{
		ID: wantEventID, Type: projections.EventSecretRotationScheduleRan,
		TenantID: tenantID, Time: *preparedCommand.PreparedAt,
		SchemaVersion: projections.SecretRotationScheduleRanEventSchemaVersion,
		Data:          payload,
	})
	if err != nil {
		return store.SecretRotationScheduleRun{}, err
	}
	return decodeSecretRotationScheduleRunEvent(ev, tenantID, in.ScheduleID, in.RunID)
}

func (o *Orchestrator) emitPreparedSecretRotationScheduleRun(
	ctx context.Context,
	next events.Event,
) (events.Event, error) {
	var ev events.Event
	err := o.store.WithPrivacyTenantProjectionRepeatableRead(
		ctx, next.TenantID, "secret rotation scheduler terminal append", func(tx pgx.Tx) error {
			var err error
			ev, err = o.log.Append(ctx, next)
			if err != nil {
				return err
			}
			return o.proj.ApplyTx(ctx, tx, ev)
		})
	return ev, err
}

// ReconcileSecretRotationScheduleRun projects a retained deterministic terminal
// event before a retry is allowed to reacquire the due edge. It closes the
// append-ACK/SQL-rollback gap without executing the connector command again.
func (o *Orchestrator) ReconcileSecretRotationScheduleRun(
	ctx context.Context,
	tenantID, scheduleID, runID string,
	dueAt time.Time,
) (store.SecretRotationScheduleRun, bool, error) {
	return o.reconcileSecretRotationScheduleRun(ctx, tenantID, scheduleID, runID,
		SecretRotationScheduleRunEventID(runID), dueAt)
}

func (o *Orchestrator) reconcileSecretRotationScheduleRun(
	ctx context.Context,
	tenantID, scheduleID, runID, eventID string,
	dueAt time.Time,
) (store.SecretRotationScheduleRun, bool, error) {
	var (
		retained store.SecretRotationScheduleRun
		found    bool
	)
	err := o.store.WithPrivacyRecoveryBarrier(
		ctx, tenantID, "secret rotation scheduler terminal replay", func(barrierCtx context.Context) error {
			command, commandErr := o.store.GetSecretRotationScheduleCommand(
				barrierCtx, tenantID, scheduleID, runID)
			var (
				ev        events.Event
				lookupErr error
			)
			switch {
			case commandErr == nil && command.Status == "privacy_erased":
				return fmt.Errorf("%w: scheduled rotation command was permanently closed by privacy erasure",
					store.ErrSecretRotationScheduleCommandConflict)
			case commandErr == nil && command.TerminalEventSequence != nil:
				terminalSequence, sequenceErr := storedSecretRotationEventSequence(*command.TerminalEventSequence)
				if sequenceErr != nil {
					return sequenceErr
				}
				ev, found, lookupErr = o.log.EventAtSequence(barrierCtx, terminalSequence)
			case commandErr == nil:
				// Only an expired claimed receiver reaches this branch. Its stable
				// event ID closes the one append-ACK window that has no SQL sequence.
				ev, found, lookupErr = o.log.EventByID(barrierCtx, eventID)
			default:
				return fmt.Errorf("orchestrator: load scheduled rotation authority for retained event: %w", commandErr)
			}
			if lookupErr != nil {
				return fmt.Errorf("orchestrator: reconcile scheduled rotation terminal event: %w", lookupErr)
			}
			if !found {
				return nil
			}
			run, decodeErr := decodeSecretRotationScheduleRunEvent(ev, tenantID, scheduleID, runID)
			if decodeErr != nil {
				return decodeErr
			}
			if validateErr := validateSecretRotationScheduleRunCommand(run, command); validateErr != nil {
				return validateErr
			}
			if !dueAt.IsZero() && !dueAt.Equal(run.DueAt) {
				return fmt.Errorf("%w: requested due edge differs from retained event",
					store.ErrSecretRotationScheduleCommandConflict)
			}
			if applyErr := o.proj.Apply(barrierCtx, ev); applyErr != nil {
				return fmt.Errorf("orchestrator: project retained scheduled rotation terminal event: %w", applyErr)
			}
			retained = run
			return nil
		})
	return retained, found, err
}

// PurgeSecretRotationScheduleCommands runs one bounded, event-safe retention
// pass. A terminal SQL receipt is reclaimable only when its exact immutable
// terminal event is still retained, the schedule projection has already
// advanced beyond that due edge, and a newer command remains as a finite
// per-schedule lineage fence. Claimed/ambiguous work is never selected or
// deleted. In steady state this retains exactly the newest command per schedule.
//
// A full rebuild remains safe after deletion: the retained current terminal event
// carries the exact due-edge tuple, reconstructs the schedule's successor edge
// without consulting wall time, and cannot re-run the deleted edge.
func (o *Orchestrator) PurgeSecretRotationScheduleCommands(
	ctx context.Context,
	tenantID string,
	limit int,
) (int, error) {
	candidates, err := o.store.ListSecretRotationScheduleCommandGCCandidates(ctx, tenantID, limit)
	if err != nil {
		return 0, fmt.Errorf("orchestrator: list scheduled rotation command GC candidates: %w", err)
	}
	purged := 0
	for _, command := range candidates {
		if command.TerminalEventSequence == nil || command.PreparedAt == nil {
			return purged, fmt.Errorf("%w: terminal command lacks constant-time event authority",
				store.ErrSecretRotationScheduleCommandConflict)
		}
		terminalSequence, sequenceErr := storedSecretRotationEventSequence(*command.TerminalEventSequence)
		if sequenceErr != nil {
			return purged, sequenceErr
		}
		deleted := false
		err := o.store.WithPrivacyRecoveryBarrier(
			ctx, tenantID, "secret rotation scheduler command GC", func(barrierCtx context.Context) error {
				ev, found, lookupErr := o.log.EventAtSequence(barrierCtx, terminalSequence)
				if lookupErr != nil {
					return fmt.Errorf("orchestrator: verify scheduled rotation terminal event for GC: %w", lookupErr)
				}
				if !found {
					// Event retention is the safety boundary. Keep the SQL receiver and
					// fail loudly so bounded GC cannot erase its source-of-truth proof.
					return fmt.Errorf("%w: terminal event %s is unavailable for command GC",
						store.ErrSecretRotationScheduleCommandConflict, command.TerminalEventID)
				}
				run, decodeErr := decodeSecretRotationScheduleRunEvent(
					ev, command.TenantID, command.ScheduleID, command.RunID)
				if decodeErr != nil {
					return decodeErr
				}
				if run.SchemaVersion != projections.SecretRotationScheduleRanEventSchemaVersion ||
					command.TerminalEventType != run.EventType ||
					terminalSequence != run.EventSequence ||
					command.TerminalEventDigest != run.EventDigest || command.Status != run.Status ||
					command.NewRef != run.NewRef || command.Error != run.Error ||
					command.PreparedStatus != run.Status || command.PreparedNewRef != run.NewRef ||
					command.PreparedError != run.Error || command.PreparedEventDigest != run.EventDigest ||
					command.PrivacyRewriteVersion != 0 || command.PrivacySubjectRef != "" ||
					command.PrivacyOperationID != "" || command.PrivacyEventID != "" ||
					command.TerminalAt == nil ||
					!command.TerminalAt.Truncate(time.Microsecond).Equal(run.RanAt.Truncate(time.Microsecond)) ||
					!command.PreparedAt.Truncate(time.Microsecond).Equal(run.RanAt.Truncate(time.Microsecond)) ||
					!run.DueAt.Equal(command.DueAt) || run.Provider != command.Provider ||
					run.Key != command.Key || run.OldRef != command.OldRef ||
					run.IntervalSeconds != command.IntervalSeconds ||
					run.ConfigEventSequence != command.ConfigEventSequence ||
					run.IdentityVersion != command.IdentityVersion ||
					run.TenantRegistrationEventID != command.TenantRegistrationEventID ||
					run.TenantRegistrationEventSequence != command.TenantRegistrationEventSequence ||
					run.CommandKey != command.CommandKey || run.RequestBinding != command.RequestBinding {
					return fmt.Errorf("%w: terminal SQL receipt differs from retained event during GC",
						store.ErrSecretRotationScheduleCommandConflict)
				}
				var purgeErr error
				deleted, purgeErr = o.store.PurgeVerifiedSecretRotationScheduleCommand(barrierCtx, command)
				return purgeErr
			})
		if err != nil {
			return purged, err
		}
		if deleted {
			purged++
		}
	}
	return purged, nil
}

func storedSecretRotationEventSequence(sequence int64) (uint64, error) {
	if sequence <= 0 {
		return 0, fmt.Errorf("%w: terminal event sequence must be positive", store.ErrSecretRotationScheduleCommandConflict)
	}
	return uint64(sequence), nil // #nosec G115 -- the positive int64 value always fits exactly in uint64 (CWE-190).
}

func decodeSecretRotationScheduleRunEvent(
	ev events.Event,
	tenantID, scheduleID, runID string,
) (store.SecretRotationScheduleRun, error) {
	wantID := SecretRotationScheduleRunEventID(runID)
	wantActor := "secret-rotation-schedule:" + scheduleID
	if ev.ID != wantID || ev.Type != projections.EventSecretRotationScheduleRan || ev.TenantID != tenantID ||
		ev.Sequence == 0 || ev.Actor == nil || ev.Actor.Subject != wantActor {
		return store.SecretRotationScheduleRun{}, fmt.Errorf(
			"%w: retained scheduled rotation terminal envelope differs", store.ErrSecretRotationScheduleCommandConflict)
	}
	var payload projections.SecretRotationScheduleRan
	if err := json.Unmarshal(ev.Data, &payload); err != nil {
		return store.SecretRotationScheduleRun{}, fmt.Errorf("orchestrator: decode scheduled rotation terminal event: %w", err)
	}
	if payload.ScheduleID != scheduleID || payload.RunID != runID || !secretRotationScheduleTerminalStatus(payload.Status) {
		return store.SecretRotationScheduleRun{}, fmt.Errorf(
			"%w: retained scheduled rotation terminal payload differs", store.ErrSecretRotationScheduleCommandConflict)
	}
	schemaVersion := ev.SchemaVersion
	if schemaVersion == 0 {
		schemaVersion = events.DefaultSchemaVersion
	}
	switch schemaVersion {
	case events.DefaultSchemaVersion:
		// Version 1 predates the durable due-edge command tuple. It remains
		// readable only so genuinely old immutable histories can rebuild.
	case rotationcommand.LegacyBoundEventSchemaVersion:
		if payload.Provider == "" || payload.Key == "" || payload.OldRef == "" || payload.IntervalSeconds <= 0 ||
			payload.ConfigEventSequence == 0 || payload.RequestBinding == "" ||
			!rotationcommand.LegacyMatches(tenantID, scheduleID, runID,
				payload.DueAt, payload.CommandKey, ev.ID) {
			return store.SecretRotationScheduleRun{}, fmt.Errorf(
				"%w: retained scheduled rotation v2 due-edge tuple differs", store.ErrSecretRotationScheduleCommandConflict)
		}
	case projections.SecretRotationScheduleRanEventSchemaVersion:
		if payload.Provider == "" || payload.Key == "" || payload.OldRef == "" || payload.IntervalSeconds <= 0 ||
			payload.ConfigEventSequence == 0 || payload.RequestBinding == "" ||
			payload.TenantRegistrationEventID == "" || payload.TenantRegistrationEventSequence == 0 ||
			!rotationcommand.Matches(tenantID, payload.TenantRegistrationEventSequence,
				scheduleID, runID, payload.DueAt, payload.CommandKey, ev.ID) {
			return store.SecretRotationScheduleRun{}, fmt.Errorf(
				"%w: retained scheduled rotation v2 due-edge tuple differs", store.ErrSecretRotationScheduleCommandConflict)
		}
	default:
		return store.SecretRotationScheduleRun{}, fmt.Errorf(
			"%w: retained scheduled rotation schema version %d is unsupported", store.ErrSecretRotationScheduleCommandConflict, schemaVersion)
	}
	return store.SecretRotationScheduleRun{
		TenantID: tenantID, IdentityVersion: schemaVersion,
		TenantRegistrationEventID:       payload.TenantRegistrationEventID,
		TenantRegistrationEventSequence: payload.TenantRegistrationEventSequence,
		ScheduleID:                      scheduleID, RunID: runID,
		SchemaVersion: schemaVersion, DueAt: payload.DueAt, Provider: payload.Provider,
		Key: payload.Key, OldRef: payload.OldRef, IntervalSeconds: payload.IntervalSeconds,
		ConfigEventSequence: payload.ConfigEventSequence, CommandKey: payload.CommandKey,
		RequestBinding: payload.RequestBinding, Status: payload.Status,
		NewRef: payload.NewRef, Error: payload.Error,
		RanAt: ev.Time, EventID: ev.ID, EventType: ev.Type, EventSequence: ev.Sequence,
		EventDigest: cryptoboundary.SHA256Hex(ev.Data),
	}, nil
}

func validateSecretRotationScheduleRunCommand(
	run store.SecretRotationScheduleRun,
	command store.SecretRotationScheduleCommand,
) error {
	if run.SchemaVersion != projections.SecretRotationScheduleRanEventSchemaVersion ||
		run.IdentityVersion != command.IdentityVersion ||
		run.TenantRegistrationEventID != command.TenantRegistrationEventID ||
		run.TenantRegistrationEventSequence != command.TenantRegistrationEventSequence ||
		!run.DueAt.Equal(command.DueAt) || run.Provider != command.Provider || run.Key != command.Key ||
		run.OldRef != command.OldRef || run.IntervalSeconds != command.IntervalSeconds ||
		run.ConfigEventSequence != command.ConfigEventSequence || run.CommandKey != command.CommandKey ||
		run.RequestBinding != command.RequestBinding || run.EventID != command.TerminalEventID {
		return fmt.Errorf("%w: retained event is not bound to the exact due-edge command", store.ErrSecretRotationScheduleCommandConflict)
	}
	return nil
}

func secretRotationScheduleTerminalStatus(status string) bool {
	switch status {
	case "completed", "queued", "failed", "rolled_back", "rollback_failed", "retire_pending", "delivery_failed", "unsupported":
		return true
	default:
		return false
	}
}
