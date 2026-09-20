// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/outboxgc"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func applyDeliveredSecretSyncFixture(ctx context.Context, s *store.Store, tenantID, jobID string, attempts int, at time.Time) error {
	job, err := s.GetSecretSyncJob(ctx, tenantID, jobID)
	if err != nil {
		return err
	}
	return s.WithTenantProjection(ctx, tenantID, func(tx pgx.Tx) error {
		return s.ApplySecretSyncTerminalEventTx(ctx, tx, store.SecretSyncTerminalEvent{
			TenantID: tenantID, TenantEpoch: job.TenantEpoch, JobID: jobID,
			Status: store.SecretSyncJobDelivered, Attempts: attempts, OccurredAt: at,
			EventID:       store.SecretSyncDeliveredEventID(tenantID, jobID),
			EventType:     projections.EventSecretSyncDelivered,
			EventSequence: job.TargetOrder + 1000000, PayloadDigest: strings.Repeat("a", 64),
		})
	})
}

func appendSecretSyncEvent(
	t *testing.T,
	s *store.Store,
	log *events.Log,
	eventType, tenantID string,
	payload any,
) events.Event {
	t.Helper()
	epoch, err := s.ApplicationSecretTenantEpoch(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("secret-sync tenant epoch: %v", err)
	}
	var eventID string
	switch value := payload.(type) {
	case projections.SecretSyncQueued:
		value.TenantEpoch = epoch
		payload = value
		eventID = store.SecretSyncQueuedEventID(tenantID, value.ID)
	case projections.SecretSyncDelivered:
		value.TenantEpoch = epoch
		payload = value
		eventID = store.SecretSyncDeliveredEventID(tenantID, value.ID)
	case projections.SecretSyncFailed:
		value.TenantEpoch = epoch
		payload = value
		eventID = store.SecretSyncFailedEventID(tenantID, value.ID)
	default:
		t.Fatalf("unsupported secret-sync event payload %T", payload)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal %s: %v", eventType, err)
	}
	event, err := log.Append(context.Background(), events.Event{
		ID: eventID, Type: eventType, TenantID: tenantID,
		SchemaVersion: projections.SecretSyncEventSchemaVersion, Data: data,
	})
	if err != nil {
		t.Fatalf("append %s: %v", eventType, err)
	}
	return event
}

func appendLegacySecretSyncEvent(
	t *testing.T,
	log *events.Log,
	eventType, tenantID string,
	payload any,
) events.Event {
	t.Helper()
	var eventID string
	switch value := payload.(type) {
	case projections.SecretSyncQueued:
		eventID = store.SecretSyncQueuedEventID(tenantID, value.ID)
	case projections.SecretSyncDelivered:
		eventID = store.SecretSyncDeliveredEventID(tenantID, value.ID)
	case projections.SecretSyncFailed:
		eventID = store.SecretSyncFailedEventID(tenantID, value.ID)
	default:
		t.Fatalf("unsupported legacy secret-sync event payload %T", payload)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	event, err := log.Append(context.Background(), events.Event{
		ID: eventID, Type: eventType, TenantID: tenantID,
		SchemaVersion: events.DefaultSchemaVersion, Data: data,
	})
	if err != nil {
		t.Fatalf("append legacy %s: %v", eventType, err)
	}
	return event
}

func TestSecretSyncFreshRebuildRejectsRetainedTargetInversionBeforeIOAUD109(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	registered := appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA,
		map[string]string{"name": "retained inversion"})
	if err := projections.New(s).Apply(ctx, registered); err != nil {
		t.Fatal(err)
	}
	appendSecretSyncEvent(t, s, log, projections.EventSecretSyncQueued, tenantA,
		projections.SecretSyncQueued{
			ID: "sync-inversion-old", SecretName: "production/database", SecretVersion: 1,
			Target: "ci", RemoteKey: "TOKEN", ValueDigest: strings.Repeat("a", 64),
			IdempotencyKey: "secret.sync.ci:sync-inversion-old", Sealed: []byte("sealed-old"),
		})
	appendSecretSyncEvent(t, s, log, projections.EventSecretSyncQueued, tenantA,
		projections.SecretSyncQueued{
			ID: "sync-inversion-new", SecretName: "production/database", SecretVersion: 2,
			Target: "ci", RemoteKey: "TOKEN", ValueDigest: strings.Repeat("b", 64),
			IdempotencyKey: "secret.sync.ci:sync-inversion-new", Sealed: []byte("sealed-new"),
		})
	appendSecretSyncEvent(t, s, log, projections.EventSecretSyncDelivered, tenantA,
		projections.SecretSyncDelivered{ID: "sync-inversion-new", Attempts: 1, RemoteVersion: "new"})

	if err := projections.New(s).Rebuild(ctx, log); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("fresh rebuild retained inversion error = %v, want fail-closed idempotency conflict", err)
	}
	var outboxRows int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'secret.sync.ci'`,
		tenantA).Scan(&outboxRows); err != nil {
		t.Fatal(err)
	}
	if outboxRows != 0 {
		t.Fatalf("failed preflight wrote %d secret-sync outbox rows, want atomic zero", outboxRows)
	}
	receiverCalls := 0
	n, err := orchestrator.NewOutbox(s).Dispatch(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		receiverCalls++
		return nil
	}))
	if err != nil || n != 0 || receiverCalls != 0 {
		t.Fatalf("dispatch after refused rebuild = (processed:%d calls:%d err:%v), want zero I/O", n, receiverCalls, err)
	}
}

func TestSecretSyncEventOnlyRecoveryFenceAllowsOnlyOfflineBootstrapAUD109(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		name := "pending"
		if terminal {
			name = "terminal"
		}
		t.Run(name+"-source-had-two-receiver-starts", func(t *testing.T) {
			ctx := context.Background()
			source := newStore(t)
			log := openLog(t)
			projector := projections.New(source)
			registered := appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA,
				map[string]string{"name": "event-only recovery fence"})
			if err := projector.Apply(ctx, registered); err != nil {
				t.Fatal(err)
			}
			queued := appendSecretSyncEvent(t, source, log, projections.EventSecretSyncQueued, tenantA,
				projections.SecretSyncQueued{
					ID: "sync-event-only-fenced", SecretName: "production/database", SecretVersion: 1,
					Target: "ci", RemoteKey: "TOKEN", ValueDigest: strings.Repeat("c", 64),
					IdempotencyKey: "secret.sync.ci:sync-event-only-fenced", Sealed: []byte("sealed"),
				})
			if err := projector.Apply(ctx, queued); err != nil {
				t.Fatal(err)
			}
			job, err := source.GetSecretSyncJob(ctx, tenantA, "sync-event-only-fenced")
			if err != nil {
				t.Fatal(err)
			}
			for want := int64(1); want <= 2; want++ {
				token, proceed, err := source.BeginSecretSyncReceiverIO(
					ctx, tenantA, job.TenantEpoch, job.ID, job.OutboxID, nil,
				)
				if err != nil || !proceed || token != want {
					t.Fatalf("source receiver generation %d = (token:%d proceed:%t err:%v)", want, token, proceed, err)
				}
			}
			if terminal {
				delivered := appendSecretSyncEvent(t, source, log, projections.EventSecretSyncDelivered, tenantA,
					projections.SecretSyncDelivered{ID: job.ID, Attempts: 2, RemoteVersion: "remote-v2"})
				if err := projector.Apply(ctx, delivered); err != nil {
					t.Fatal(err)
				}
			}
			sourceAuthority, err := source.SecretSyncReceiverAuthority(ctx, tenantA, job.ID)
			if err != nil {
				t.Fatal(err)
			}
			if sourceAuthority.EffectState != store.SecretSyncReceiverEffectPossible ||
				sourceAuthority.ReceiverIOStarts != 2 {
				t.Fatalf("source receiver authority = %+v, want two-start ambiguity", sourceAuthority)
			}

			// A new store is the event-only recovery target. Its first replay cannot
			// reconstruct the source's two receiver starts from AN-2 history.
			restored := newStore(t)
			if err := restored.FenceSecretSyncReceiverRecovery(ctx, "event_only_restore"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := restored.AuthorizeSecretSyncReceiverRecovery(context.Background()); err != nil {
					t.Errorf("restore secret-sync recovery authority after test: %v", err)
				}
			})
			if err := projections.New(restored).Rebuild(ctx, log); !errors.Is(err, store.ErrSecretSyncReceiverRecoveryFenced) {
				t.Fatalf("ordinary rebuild behind event-only fence = %v, want durable recovery fence", err)
			}
			if err := projections.New(restored, projections.WithSecretSyncRecoveryBootstrap()).Rebuild(ctx, log); err != nil {
				t.Fatalf("offline recovery bootstrap rebuild: %v", err)
			}
			rebuilt, err := restored.GetSecretSyncJob(ctx, tenantA, job.ID)
			if err != nil {
				t.Fatal(err)
			}
			receiverCalls := 0
			_, proceed, beginErr := restored.BeginSecretSyncReceiverIO(
				ctx, tenantA, rebuilt.TenantEpoch, rebuilt.ID, rebuilt.OutboxID, nil,
			)
			if proceed {
				receiverCalls++
			}
			if !errors.Is(beginErr, store.ErrSecretSyncReceiverRecoveryFenced) || proceed {
				t.Fatalf("receiver start behind event-only fence = (proceed:%t err:%v), want zero-I/O refusal", proceed, beginErr)
			}
			if receiverCalls != 0 {
				t.Fatalf("event-only %s recovery made %d receiver calls", name, receiverCalls)
			}
			authority, err := restored.SecretSyncReceiverAuthority(ctx, tenantA, rebuilt.ID)
			if err != nil {
				t.Fatal(err)
			}
			if terminal {
				if authority.JobStatus != store.SecretSyncJobDelivered ||
					authority.EffectState != store.SecretSyncReceiverEffectPossible ||
					authority.ReceiverIOStarts != 1 {
					t.Fatalf("event-only terminal replay authority = %+v, want deliberately inexact one-start projection behind fence", authority)
				}
			} else if authority.JobStatus != store.SecretSyncJobPending ||
				authority.EffectState != store.SecretSyncReceiverNoEffect || authority.ReceiverIOStarts != 0 {
				t.Fatalf("event-only pending replay authority = %+v, want deliberately inexact zero-start projection behind fence", authority)
			}
			if err := restored.AuthorizeSecretSyncReceiverRecovery(ctx); err != nil {
				t.Fatal(err)
			}
			if err := projections.New(restored).ProjectCatchUp(ctx, log); err != nil {
				t.Fatalf("ordinary startup stayed fenced after explicit coordinator authorization: %v", err)
			}
			if !terminal {
				if token, proceed, err := restored.BeginSecretSyncReceiverIO(
					ctx, tenantA, rebuilt.TenantEpoch, rebuilt.ID, rebuilt.OutboxID, nil,
				); err != nil || !proceed || token != 1 {
					t.Fatalf("authorized receiver start = (token:%d proceed:%t err:%v), want first generation", token, proceed, err)
				}
			}
		})
	}
}

func TestSecretSyncCompletedThenOffboardedPassesWarmStartAndZeroStateRebuildAUD109(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	projector := projections.New(s)
	apply := func(event events.Event) {
		t.Helper()
		if err := projector.Apply(ctx, event); err != nil {
			t.Fatalf("apply %s: %v", event.Type, err)
		}
	}

	apply(appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "Acme"}))
	queued := appendSecretSyncEvent(t, s, log, projections.EventSecretSyncQueued, tenantA, projections.SecretSyncQueued{
		ID: "sync-complete-before-offboard", SecretName: "production/database", SecretVersion: 1,
		Target: "ci", RemoteKey: "TOKEN", ValueDigest: strings.Repeat("a", 64),
		IdempotencyKey: "secret.sync.ci:sync-complete-before-offboard", Sealed: []byte("sealed"),
	})
	apply(queued)
	apply(appendSecretSyncEvent(t, s, log, projections.EventSecretSyncDelivered, tenantA,
		projections.SecretSyncDelivered{ID: "sync-complete-before-offboard", Attempts: 1}))
	// The domain event is durable before the generic outbox finalizer. Complete
	// that zero-receiver-I/O cleanup step before offboarding; an offboard racing
	// the recognized terminal-job/pending-outbox crash window must fail closed.
	if n, err := orchestrator.NewOutbox(s).Dispatch(ctx, orchestrator.HandlerFunc(
		func(context.Context, orchestrator.Message) error { return nil },
	)); err != nil || n != 1 {
		t.Fatalf("finalize delivered secret-sync outbox = (%d,%v), want (1,nil)", n, err)
	}
	offboarded := appendJSONEvent(t, log, projections.EventTenantOffboarded, tenantA, map[string]int{"rows_deleted": 1})
	apply(offboarded)
	if err := projector.AdvanceCheckpoint(ctx, offboarded.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("completed->offboard warm catch-up: %v", err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("completed->offboard zero-state rebuild: %v", err)
	}
	if _, err := s.GetSecretSyncJob(ctx, tenantA, "sync-complete-before-offboard"); !store.IsNotFound(err) {
		t.Fatalf("offboarded completed job survived rebuild: %v", err)
	}
}

func TestLateLegacySecretSyncTerminalIsInertInEveryReplayModeAUD109(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	projector := projections.New(s)
	apply := func(event events.Event) {
		t.Helper()
		if err := projector.Apply(ctx, event); err != nil {
			t.Fatalf("apply %s: %v", event.Type, err)
		}
	}

	apply(appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "old"}))
	const jobID = "sync-legacy-late-terminal"
	apply(appendLegacySecretSyncEvent(t, log, projections.EventSecretSyncQueued, tenantA, projections.SecretSyncQueued{
		ID: jobID, SecretName: "old/source", SecretVersion: 1,
		Target: "ci", RemoteKey: "TOKEN", ValueDigest: strings.Repeat("b", 64),
		IdempotencyKey: "secret.sync.ci:" + jobID, Sealed: []byte("old-sealed"),
	}))
	apply(appendJSONEvent(t, log, projections.EventTenantOffboarded, tenantA, map[string]int{"rows_deleted": 1}))
	reregistered := appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "new"})
	apply(reregistered)
	if err := projector.AdvanceCheckpoint(ctx, reregistered.Sequence); err != nil {
		t.Fatal(err)
	}
	if count, err := projector.Snapshot(ctx); err != nil || count != 1 {
		t.Fatalf("snapshot new lifecycle = (%d, %v), want (1, nil)", count, err)
	}
	lateTerminal := appendLegacySecretSyncEvent(t, log, projections.EventSecretSyncFailed, tenantA,
		projections.SecretSyncFailed{ID: jobID, Attempts: 2, Error: "closed late failure"})

	tailCtx, cancelTail := context.WithCancel(ctx)
	tailDone := make(chan error, 1)
	go func() {
		tailDone <- projections.NewTailWorker(log, projector, nil, time.Second).Run(tailCtx)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		checkpoint, err := s.ProjectionCheckpoint(ctx)
		if err != nil {
			cancelTail()
			t.Fatal(err)
		}
		if checkpoint >= lateTerminal.Sequence {
			break
		}
		if time.Now().After(deadline) {
			cancelTail()
			t.Fatalf("live tail did not advance across inert terminal: checkpoint=%d want=%d", checkpoint, lateTerminal.Sequence)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancelTail()
	if err := <-tailDone; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("live tail stop: %v", err)
	}
	if _, err := s.GetSecretSyncJob(ctx, tenantA, jobID); !store.IsNotFound(err) {
		t.Fatalf("live tail resurrected late legacy terminal: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx, `UPDATE projection_checkpoint SET applied_seq = $1 WHERE id = 1`, reregistered.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("catch-up late legacy terminal: %v", err)
	}
	if _, err := s.GetSecretSyncJob(ctx, tenantA, jobID); !store.IsNotFound(err) {
		t.Fatalf("catch-up resurrected late legacy terminal: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx, `UPDATE projection_checkpoint SET applied_seq = 0 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if restored, err := projector.RestoreFromSnapshot(ctx, log); err != nil || !restored {
		t.Fatalf("snapshot-tail late legacy terminal = (%t, %v), want (true, nil)", restored, err)
	}
	if _, err := s.GetSecretSyncJob(ctx, tenantA, jobID); !store.IsNotFound(err) {
		t.Fatalf("snapshot-tail resurrected late legacy terminal: %v", err)
	}
	if err := projector.Project(ctx, log); err != nil {
		t.Fatalf("full project late legacy terminal: %v", err)
	}
	if _, err := s.GetSecretSyncJob(ctx, tenantA, jobID); !store.IsNotFound(err) {
		t.Fatalf("full project resurrected late legacy terminal: %v", err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild late legacy terminal: %v", err)
	}
	if _, err := s.GetSecretSyncJob(ctx, tenantA, jobID); !store.IsNotFound(err) {
		t.Fatalf("rebuild resurrected late legacy terminal: %v", err)
	}
}

func TestSecretSyncCatchUpRejectsCheckpointAheadOfTerminalEvidenceAUD109(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	projector := projections.New(s)
	tenantEvent := appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "Acme"})
	if err := projector.Apply(ctx, tenantEvent); err != nil {
		t.Fatal(err)
	}
	queued := appendSecretSyncEvent(t, s, log, projections.EventSecretSyncQueued, tenantA, projections.SecretSyncQueued{
		ID: "sync-checkpoint-ahead", SecretName: "production/database", SecretVersion: 1,
		Target: "ci", RemoteKey: "TOKEN", ValueDigest: strings.Repeat("a", 64),
		IdempotencyKey: "secret.sync.ci:sync-checkpoint-ahead", Sealed: []byte("sealed"),
	})
	if err := projector.Apply(ctx, queued); err != nil {
		t.Fatal(err)
	}
	terminal := appendSecretSyncEvent(t, s, log, projections.EventSecretSyncDelivered, tenantA,
		projections.SecretSyncDelivered{ID: "sync-checkpoint-ahead", Attempts: 1})
	if _, err := s.SystemPool().Exec(ctx, `
		UPDATE projection_checkpoint SET applied_seq = $1, updated_at = now() WHERE id = 1`,
		terminal.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := projector.ProjectCatchUp(ctx, log); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("checkpoint-ahead catch-up error=%v, want fail-closed idempotency conflict", err)
	}
	job, err := s.GetSecretSyncJob(ctx, tenantA, "sync-checkpoint-ahead")
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != store.SecretSyncJobPending {
		t.Fatalf("checkpoint-ahead job status=%q, want pending barrier retained", job.Status)
	}
}

func TestSecretSyncWarmCheckpointAndSnapshotRejectTerminalSemanticMismatchMatrixAUD109(t *testing.T) {
	type mutation struct {
		name string
		run  func(*testing.T, context.Context, *store.Store, store.SecretSyncJob)
	}
	mutations := []mutation{
		{
			name: "same-status receipt drift",
			run: func(t *testing.T, ctx context.Context, s *store.Store, job store.SecretSyncJob) {
				setSecretSyncReplicaFixture(t, ctx, s, `UPDATE secret_sync_jobs SET attempts = attempts + 1 WHERE tenant_id = $1 AND id = $2`, job.TenantID, job.ID)
			},
		},
		{
			name: "opposite status",
			run: func(t *testing.T, ctx context.Context, s *store.Store, job store.SecretSyncJob) {
				setSecretSyncReplicaFixture(t, ctx, s, `
					UPDATE secret_sync_jobs
					   SET status = 'failed', remote_version = '', last_error = 'forged opposite outcome',
					       delivered_at = NULL, terminal_event_id = $3,
					       terminal_event_type = 'secret.sync.failed'
					 WHERE tenant_id = $1 AND id = $2`,
					job.TenantID, job.ID, store.SecretSyncFailedEventID(job.TenantID, job.ID))
			},
		},
		{
			name: "outbox destination",
			run: func(t *testing.T, ctx context.Context, s *store.Store, job store.SecretSyncJob) {
				setSecretSyncReplicaFixture(t, ctx, s, `UPDATE outbox SET destination = 'secret.sync.other' WHERE tenant_id = $1 AND id = $2`, job.TenantID, job.OutboxID)
			},
		},
		{
			name: "outbox order provenance",
			run: func(t *testing.T, ctx context.Context, s *store.Store, job store.SecretSyncJob) {
				setSecretSyncReplicaFixture(t, ctx, s, `UPDATE outbox SET secret_sync_target_order = -secret_sync_target_order, secret_sync_order_from_event = false WHERE tenant_id = $1 AND id = $2`, job.TenantID, job.OutboxID)
			},
		},
		{
			name: "outbox status",
			run: func(t *testing.T, ctx context.Context, s *store.Store, job store.SecretSyncJob) {
				setSecretSyncReplicaFixture(t, ctx, s, `UPDATE outbox SET status = 'failed' WHERE tenant_id = $1 AND id = $2`, job.TenantID, job.OutboxID)
			},
		},
		{
			name: "paired outbox",
			run: func(t *testing.T, ctx context.Context, s *store.Store, job store.SecretSyncJob) {
				var (
					otherOutboxID int64
					otherJobID    string
				)
				if err := s.SystemPool().QueryRow(ctx, `
					SELECT queued.id, other_job.id
					  FROM outbox AS queued
					  JOIN secret_sync_jobs AS other_job
					    ON other_job.tenant_id = queued.tenant_id
					   AND other_job.outbox_id = queued.id
					 WHERE queued.tenant_id = $1 AND queued.id <> $2
					   AND queued.destination = 'secret.sync.ci'
					 ORDER BY queued.id LIMIT 1`, job.TenantID, job.OutboxID).Scan(&otherOutboxID, &otherJobID); err != nil {
					t.Fatal(err)
				}
				// Swap the two real outbox identities through a temporary value. A
				// direct one-row reassignment is correctly blocked by the unique
				// (tenant_id,outbox_id) invariant before this recovery test can
				// exercise the intended cross-pair mismatch.
				temporaryOutboxID := job.OutboxID + otherOutboxID + 1_000_000
				setSecretSyncReplicaFixture(t, ctx, s, `UPDATE secret_sync_jobs SET outbox_id = $3 WHERE tenant_id = $1 AND id = $2`, job.TenantID, job.ID, temporaryOutboxID)
				setSecretSyncReplicaFixture(t, ctx, s, `UPDATE secret_sync_jobs SET outbox_id = $3 WHERE tenant_id = $1 AND id = $2`, job.TenantID, otherJobID, job.OutboxID)
				setSecretSyncReplicaFixture(t, ctx, s, `UPDATE secret_sync_jobs SET outbox_id = $3 WHERE tenant_id = $1 AND id = $2`, job.TenantID, job.ID, otherOutboxID)
			},
		},
	}

	for _, mode := range []string{"checkpoint", "snapshot"} {
		for _, candidate := range mutations {
			t.Run(mode+"/"+candidate.name, func(t *testing.T) {
				ctx := context.Background()
				s := newStore(t)
				log := openLog(t)
				projector := projections.New(s)
				registered := appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "Acme"})
				if err := projector.Apply(ctx, registered); err != nil {
					t.Fatal(err)
				}
				queued := appendSecretSyncEvent(t, s, log, projections.EventSecretSyncQueued, tenantA, projections.SecretSyncQueued{
					ID: "sync-warm-matrix", SecretName: "production/database", SecretVersion: 1,
					Target: "ci", RemoteKey: "TOKEN", ValueDigest: strings.Repeat("c", 64),
					IdempotencyKey: "secret.sync.ci:sync-warm-matrix", Sealed: []byte("sealed-matrix"),
				})
				if err := projector.Apply(ctx, queued); err != nil {
					t.Fatal(err)
				}
				terminal := appendSecretSyncEvent(t, s, log, projections.EventSecretSyncDelivered, tenantA,
					projections.SecretSyncDelivered{ID: "sync-warm-matrix", Attempts: 1})
				if err := projector.Apply(ctx, terminal); err != nil {
					t.Fatal(err)
				}
				// A second current-lifecycle command supplies a real but wrong paired
				// outbox for that matrix case.
				second := appendSecretSyncEvent(t, s, log, projections.EventSecretSyncQueued, tenantA, projections.SecretSyncQueued{
					ID: "sync-warm-matrix-other", SecretName: "production/database", SecretVersion: 2,
					Target: "ci", RemoteKey: "TOKEN_2", ValueDigest: strings.Repeat("d", 64),
					IdempotencyKey: "secret.sync.ci:sync-warm-matrix-other", Sealed: []byte("sealed-other"),
				})
				if err := projector.Apply(ctx, second); err != nil {
					t.Fatal(err)
				}
				if err := projector.AdvanceCheckpoint(ctx, second.Sequence); err != nil {
					t.Fatal(err)
				}
				if mode == "snapshot" {
					if count, err := projector.Snapshot(ctx); err != nil || count != 1 {
						t.Fatalf("snapshot warm matrix = (%d, %v)", count, err)
					}
				}
				job, err := s.GetSecretSyncJob(ctx, tenantA, "sync-warm-matrix")
				if err != nil {
					t.Fatal(err)
				}
				candidate.run(t, ctx, s, job)
				if mode == "snapshot" {
					if _, err := s.SystemPool().Exec(ctx, `UPDATE projection_checkpoint SET applied_seq = 0 WHERE id = 1`); err != nil {
						t.Fatal(err)
					}
					_, err = projector.RestoreFromSnapshot(ctx, log)
				} else {
					err = projector.ProjectCatchUp(ctx, log)
				}
				if !errors.Is(err, store.ErrIdempotencyConflict) {
					t.Fatalf("warm %s accepted %s mismatch: %v", mode, candidate.name, err)
				}
			})
		}
	}
}

func TestSecretSyncLegacyFailedMigrationAuthoritySurvivesColdRebuildAUD109(t *testing.T) {
	for _, receiverStarts := range []int64{1, 2} {
		t.Run(fmt.Sprintf("receiver-starts-%d", receiverStarts), func(t *testing.T) {
			ctx := context.Background()
			s := newStore(t)
			log := openLog(t)
			projector := projections.New(s)
			registered := appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA,
				map[string]string{"name": "legacy failed migration"})
			if err := projector.Apply(ctx, registered); err != nil {
				t.Fatal(err)
			}
			queued := appendLegacySecretSyncEvent(t, log, projections.EventSecretSyncQueued, tenantA,
				projections.SecretSyncQueued{
					ID: "sync-legacy-failed-startup", SecretName: "production/database", SecretVersion: 1,
					Target: "airgap", RemoteKey: "TOKEN", ValueDigest: strings.Repeat("e", 64),
					IdempotencyKey: "secret.sync.airgap:sync-legacy-failed-startup", Sealed: []byte("sealed"),
				})
			if err := projector.Apply(ctx, queued); err != nil {
				t.Fatal(err)
			}
			terminal := appendLegacySecretSyncEvent(t, log, projections.EventSecretSyncFailed, tenantA,
				projections.SecretSyncFailed{
					ID: "sync-legacy-failed-startup", Attempts: 1,
					Error: "legacy receiver failure",
				})
			if err := projector.Apply(ctx, terminal); err != nil {
				t.Fatal(err)
			}
			job, err := s.GetSecretSyncJob(ctx, tenantA, "sync-legacy-failed-startup")
			if err != nil {
				t.Fatal(err)
			}

			// Reproduce exactly what migration 0153 can know about an inherited
			// failed command. One or many starts remain ambiguous across both warm
			// validation and a cold, atomic rebuild.
			setSecretSyncReplicaFixture(t, ctx, s, `
				UPDATE secret_sync_jobs
				   SET target_order = -target_order,
				       terminal_event_id = 'legacy-0153-secret-sync:' || tenant_id::text || ':' || id,
				       terminal_event_type = 'legacy.secret.sync.failed',
				       terminal_event_sequence = abs(target_order),
				       terminal_event_digest = repeat('a', 64),
				       terminal_event_from_event = false
				 WHERE tenant_id = $1 AND id = $2`, tenantA, job.ID)
			setSecretSyncReplicaFixture(t, ctx, s, `
				UPDATE outbox
				   SET secret_sync_target_order = -secret_sync_target_order,
				       secret_sync_order_from_event = false,
				       secret_sync_receiver_effect_state = 'effect_possible',
				       secret_sync_receiver_io_starts = $3,
				       secret_sync_failure_detail = '',
				       secret_sync_failure_attempts = 0
				 WHERE tenant_id = $1 AND id = $2`, tenantA, job.OutboxID, receiverStarts)

			if err := projector.Rebuild(ctx, log); err != nil {
				t.Fatalf("cold rebuild rejected migration-authored failed authority: %v", err)
			}
			reconciled, err := s.GetSecretSyncJob(ctx, tenantA, job.ID)
			if err != nil {
				t.Fatal(err)
			}
			if reconciled.TargetOrder >= 0 || reconciled.TerminalEventFromEvent == nil ||
				!*reconciled.TerminalEventFromEvent || reconciled.TerminalEventID != terminal.ID ||
				reconciled.TerminalEventSequence == nil || *reconciled.TerminalEventSequence != int64(terminal.Sequence) { // #nosec G115 -- embedded JetStream fixture sequences are bounded far below MaxInt64 (CWE-190).
				t.Fatalf("reconciled migration receipt = %+v, want exact retained terminal event and negative order", reconciled)
			}
			authority, err := s.SecretSyncReceiverAuthority(ctx, tenantA, job.ID)
			if err != nil {
				t.Fatal(err)
			}
			if authority.EffectState != store.SecretSyncReceiverEffectPossible ||
				authority.ReceiverIOStarts != receiverStarts || authority.FailureDetail != "" || authority.FailureAttempts != 0 {
				t.Fatalf("reconciled migration receiver authority = %+v, want conservative ambiguity retained", authority)
			}
			if _, err := s.OffboardTenant(ctx, tenantA); err == nil {
				t.Fatal("legacy ambiguous failed receiver allowed tenant offboard")
			} else {
				var busy *store.TenantSecretSyncNotQuiescentError
				if !errors.As(err, &busy) || busy.JobID != job.ID || busy.ReceiverIOStarts != receiverStarts {
					t.Fatalf("legacy ambiguous offboard error = %v, want exact receiver barrier", err)
				}
			}

			successorEvent := appendSecretSyncEvent(t, s, log, projections.EventSecretSyncQueued, tenantA,
				projections.SecretSyncQueued{
					ID: "sync-after-legacy-failure", SecretName: "production/database", SecretVersion: 2,
					Target: "airgap", RemoteKey: "TOKEN", ValueDigest: strings.Repeat("f", 64),
					IdempotencyKey: "secret.sync.airgap:sync-after-legacy-failure", Sealed: []byte("sealed-next"),
				})
			if err := projector.Apply(ctx, successorEvent); err != nil {
				t.Fatal(err)
			}
			successor, err := s.GetSecretSyncJob(ctx, tenantA, "sync-after-legacy-failure")
			if err != nil {
				t.Fatal(err)
			}
			blocked, err := s.SecretSyncHasOlderNonterminal(ctx, tenantA, "airgap", successor.OutboxID)
			if err != nil || !blocked {
				t.Fatalf("successor behind legacy ambiguity = (blocked:%t, %v), want permanent FIFO barrier", blocked, err)
			}
		})
	}
}

func setSecretSyncReplicaFixture(t *testing.T, ctx context.Context, s *store.Store, query string, args ...any) {
	t.Helper()
	conn, err := s.SystemPool().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := conn.Exec(context.Background(), `SET session_replication_role = origin`); err != nil {
			t.Errorf("restore session_replication_role: %v", err)
		}
	}()
	if _, err := conn.Exec(ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}

func TestSecretSyncRebuildKeepsLateOldLifecycleTerminalInertAUD109(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	projector := projections.New(s)
	registered := appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "old"})
	if err := projector.Apply(ctx, registered); err != nil {
		t.Fatal(err)
	}
	oldEpoch, err := s.ApplicationSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	appendSecretSyncEvent(t, s, log, projections.EventSecretSyncQueued, tenantA, projections.SecretSyncQueued{
		ID: "sync-late-old-terminal", SecretName: "old/source", SecretVersion: 1,
		Target: "ci", RemoteKey: "TOKEN", ValueDigest: strings.Repeat("b", 64),
		IdempotencyKey: "secret.sync.ci:sync-late-old-terminal", Sealed: []byte("old-sealed"),
	})
	appendJSONEvent(t, log, projections.EventTenantOffboarded, tenantA, map[string]int{"rows_deleted": 1})
	appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "new"})
	terminal := projections.SecretSyncDelivered{ID: "sync-late-old-terminal", TenantEpoch: oldEpoch, Attempts: 1}
	data, err := json.Marshal(terminal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		ID:   store.SecretSyncDeliveredEventID(tenantA, terminal.ID),
		Type: projections.EventSecretSyncDelivered, TenantID: tenantA,
		SchemaVersion: projections.SecretSyncEventSchemaVersion, Data: data,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx, `
		UPDATE application_secret_tenant_epochs SET epoch_id = gen_random_uuid()
		 WHERE tenant_id = $1`, tenantA); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild with late old-lifecycle terminal: %v", err)
	}
	if _, err := s.GetSecretSyncJob(ctx, tenantA, terminal.ID); !store.IsNotFound(err) {
		t.Fatalf("late old-lifecycle terminal resurrected job: %v", err)
	}
}

func TestSecretSyncEventOrderWaitsForOrderedProjectionCheckpointAUD109(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := newStore(t)
	log := openLog(t)
	projector := projections.New(s)

	tenantEvent := appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "Acme"})
	if err := projector.Apply(ctx, tenantEvent); err != nil {
		t.Fatal(err)
	}
	queued := func(id, key string) events.Event {
		t.Helper()
		return appendSecretSyncEvent(t, s, log, projections.EventSecretSyncQueued, tenantA, projections.SecretSyncQueued{
			ID: id, SecretName: "production/database", SecretVersion: 1,
			Target: "ci", RemoteKey: key, ValueDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			IdempotencyKey: "secret.sync.ci:" + id, Sealed: []byte("sealed-" + id),
		})
	}
	seq2 := queued("sync-event-order-v2", "/TOKEN/")
	seq3 := queued("sync-event-order-v3", "TOKEN")
	if seq2.Sequence == 0 || seq3.Sequence != seq2.Sequence+1 {
		t.Fatalf("fixture sequences v2=%d v3=%d, want adjacent positive events", seq2.Sequence, seq3.Sequence)
	}

	// Hold only v2's per-command projection lock. v3 then commits first and receives
	// the lower outbox id, reproducing the exact DB-order inversion that target_order
	// must not confuse with AN-2 order.
	lockTx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lockTx.Rollback(ctx) }()
	if _, err := lockTx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"secret-sync-intent\x1f"+tenantA+"\x1f"+"sync-event-order-v2"); err != nil {
		t.Fatal(err)
	}
	v2Done := make(chan error, 1)
	go func() { v2Done <- projector.Apply(ctx, seq2) }()
	if err := projector.Apply(ctx, seq3); err != nil {
		t.Fatalf("commit v3 projection first: %v", err)
	}
	v3, err := s.GetSecretSyncJob(ctx, tenantA, "sync-event-order-v3")
	if err != nil {
		t.Fatal(err)
	}
	if v3.TargetOrder != int64(seq3.Sequence) { // #nosec G115 -- fixture sequence is tiny and asserted positive above.
		t.Fatalf("v3 target order=%d, want event sequence %d", v3.TargetOrder, seq3.Sequence)
	}

	delivered := make([]string, 0, 2)
	outbox := orchestrator.NewOutbox(s)
	handler := orchestrator.HandlerFunc(func(_ context.Context, message orchestrator.Message) error {
		var payload struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(message.Payload, &payload); err != nil {
			return err
		}
		delivered = append(delivered, payload.ID)
		return applyDeliveredSecretSyncFixture(ctx, s, message.TenantID, payload.ID, message.Attempts, time.Now().UTC())
	})
	if n, err := outbox.Dispatch(ctx, handler); err != nil || n != 0 {
		t.Fatalf("current claim before ordered checkpoint=(%d,%v), want (0,nil)", n, err)
	}
	oldClaim, err := s.SystemPool().Exec(ctx, `
		UPDATE outbox
		   SET status = 'processing', attempts = attempts + 1,
		       worker_id = 'old-worker', lease_until = now() + interval '1 minute'
		 WHERE tenant_id = $1 AND id = $2 AND status = 'pending'`, tenantA, v3.OutboxID)
	if err != nil || oldClaim.RowsAffected() != 0 {
		t.Fatalf("old claim before ordered checkpoint=(%d,%v), want (0,nil)", oldClaim.RowsAffected(), err)
	}
	var attempts int
	if err := s.SystemPool().QueryRow(ctx, `SELECT attempts FROM outbox WHERE id = $1`, v3.OutboxID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 {
		t.Fatalf("checkpoint-blocked old claim consumed attempts=%d, want 0", attempts)
	}

	if err := lockTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-v2Done; err != nil {
		t.Fatalf("commit delayed v2 projection: %v", err)
	}
	v2, err := s.GetSecretSyncJob(ctx, tenantA, "sync-event-order-v2")
	if err != nil {
		t.Fatal(err)
	}
	if v2.OutboxID <= v3.OutboxID {
		t.Fatalf("fixture outbox ids v2=%d v3=%d, want DB commit/allocation order opposite event order", v2.OutboxID, v3.OutboxID)
	}
	if n, err := outbox.Dispatch(ctx, handler); err != nil || n != 0 {
		t.Fatalf("stalled-tail claim after both live projections=(%d,%v), want (0,nil)", n, err)
	}

	// ProjectCatchUp is the ordered tail stand-in: it applies v2 before v3 and only
	// then advances the global checkpoint through v3. The dispatcher may now drain
	// both, but must deliver v2 first even though v3 has the lower outbox id.
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("ordered catch-up: %v", err)
	}
	if n, err := outbox.Dispatch(ctx, handler); err != nil || n != 2 {
		t.Fatalf("checkpoint-authenticated dispatch=(%d,%v), want (2,nil)", n, err)
	}
	want := []string{"sync-event-order-v2", "sync-event-order-v3"}
	if len(delivered) != len(want) || delivered[0] != want[0] || delivered[1] != want[1] {
		t.Fatalf("receiver order=%v, want %v", delivered, want)
	}
}

func TestSecretSyncSnapshotRestoresExactCheckpointAuthenticatedOrderAUD109(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	projector := projections.New(s)
	mustAppend(t, log, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegistered("snapshot-order"),
	})
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("project snapshot tenant registration: %v", err)
	}
	appendQueued := func(id, key string) {
		t.Helper()
		appendSecretSyncEvent(t, s, log, projections.EventSecretSyncQueued, tenantA, projections.SecretSyncQueued{
			ID: id, SecretName: "production/database", SecretVersion: 1,
			Target: "ci", RemoteKey: key, ValueDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			IdempotencyKey: "secret.sync.ci:" + id, Sealed: []byte("sealed-" + id),
		})
	}
	appendQueued("sync-snapshot-v2", "/TOKEN/")
	appendQueued("sync-snapshot-v3", "TOKEN")
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	beforeV2, err := s.GetSecretSyncJob(ctx, tenantA, "sync-snapshot-v2")
	if err != nil {
		t.Fatal(err)
	}
	beforeV3, err := s.GetSecretSyncJob(ctx, tenantA, "sync-snapshot-v3")
	if err != nil {
		t.Fatal(err)
	}
	if beforeV2.TargetOrder >= beforeV3.TargetOrder {
		t.Fatalf("pre-snapshot target order v2=%d v3=%d", beforeV2.TargetOrder, beforeV3.TargetOrder)
	}
	if n, err := projector.Snapshot(ctx); err != nil || n != 1 {
		t.Fatalf("Snapshot=(%d,%v), want (1,nil)", n, err)
	}
	var payloadOrders []int64
	if err := s.SystemPool().QueryRow(ctx, `
		SELECT array_agg((entry ->> 'target_order')::bigint ORDER BY ordinal)
		  FROM read_model_snapshots snapshot,
		       jsonb_array_elements(snapshot.payload -> 'secret_sync_jobs')
		           WITH ORDINALITY AS rows(entry, ordinal)
		 WHERE snapshot.tenant_id = $1`, tenantA).Scan(&payloadOrders); err != nil {
		t.Fatal(err)
	}
	if len(payloadOrders) != 2 || payloadOrders[0] != beforeV2.TargetOrder || payloadOrders[1] != beforeV3.TargetOrder {
		t.Fatalf("snapshot payload target order=%v, want [%d %d]", payloadOrders, beforeV2.TargetOrder, beforeV3.TargetOrder)
	}

	truncateReadModelAndCheckpoint(t, s)
	restored, err := projector.RestoreFromSnapshot(ctx, log)
	if err != nil || !restored {
		t.Fatalf("RestoreFromSnapshot=(%t,%v), want (true,nil)", restored, err)
	}
	afterV2, err := s.GetSecretSyncJob(ctx, tenantA, beforeV2.ID)
	if err != nil {
		t.Fatal(err)
	}
	afterV3, err := s.GetSecretSyncJob(ctx, tenantA, beforeV3.ID)
	if err != nil {
		t.Fatal(err)
	}
	if afterV2.TargetOrder != beforeV2.TargetOrder || afterV3.TargetOrder != beforeV3.TargetOrder {
		t.Fatalf("restored target order v2=%d/%d v3=%d/%d",
			afterV2.TargetOrder, beforeV2.TargetOrder, afterV3.TargetOrder, beforeV3.TargetOrder)
	}

	var delivered []string
	handler := orchestrator.HandlerFunc(func(_ context.Context, message orchestrator.Message) error {
		var payload struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(message.Payload, &payload); err != nil {
			return err
		}
		delivered = append(delivered, payload.ID)
		return applyDeliveredSecretSyncFixture(ctx, s, message.TenantID, payload.ID, message.Attempts, time.Now().UTC())
	})
	if n, err := orchestrator.NewOutbox(s).Dispatch(ctx, handler); err != nil || n != 2 {
		t.Fatalf("snapshot-authenticated dispatch=(%d,%v), want (2,nil)", n, err)
	}
	if len(delivered) != 2 || delivered[0] != beforeV2.ID || delivered[1] != beforeV3.ID {
		t.Fatalf("snapshot receiver order=%v, want [%s %s]", delivered, beforeV2.ID, beforeV3.ID)
	}
}

func TestSecretIntegrationEventsRebuildLeaseAndSealedOutbox(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	projector := projections.New(s)
	apply := func(eventType string, payload any) {
		t.Helper()
		var event events.Event
		switch eventType {
		case projections.EventSecretSyncQueued, projections.EventSecretSyncDelivered, projections.EventSecretSyncFailed:
			event = appendSecretSyncEvent(t, s, log, eventType, tenantA, payload)
		default:
			event = appendJSONEvent(t, log, eventType, tenantA, payload)
		}
		if err := projector.Apply(ctx, event); err != nil {
			t.Fatalf("apply %s: %v", eventType, err)
		}
	}

	apply(projections.EventTenantRegistered, map[string]string{"name": "Acme"})
	now := time.Now().UTC()
	apply(projections.EventDynamicSecretLeasePending, projections.DynamicSecretLeasePending{
		ID: "lease-restart", IdempotencyKey: "issue-restart", Provider: "postgres-production", Role: "reader",
		ExpiresAt: now.Add(time.Hour), HardExpiresAt: now.Add(2 * time.Hour),
	})
	apply(projections.EventDynamicSecretLeasePrepared, projections.DynamicSecretLeasePrepared{
		ID: "lease-restart", Provider: "postgres-production", SealedPreparation: []byte("sealed-worker-preparation"),
	})
	apply(projections.EventDynamicSecretLeaseIssued, projections.DynamicSecretLeaseIssued{
		ID: "lease-restart", IdempotencyKey: "issue-restart", Provider: "postgres-production", Role: "reader",
		BackendRef: "trstctl_reader_restart", SealedCredential: []byte("sealed-dynamic-credential"),
		ExpiresAt: now.Add(time.Hour), HardExpiresAt: now.Add(2 * time.Hour),
	})
	apply(projections.EventDynamicSecretLeaseRevocationRequested, projections.DynamicSecretLeaseRevocationRequested{
		ID: "lease-restart", Provider: "postgres-production", BackendRef: "trstctl_reader_restart",
	})

	ciphertext := []byte("ciphertext-only-not-a-secret-value")
	apply(projections.EventSecretSyncQueued, projections.SecretSyncQueued{
		ID: "sync-restart", SecretName: "production/database", SecretVersion: 4,
		Target: "github-production", RemoteKey: "DATABASE_URL",
		ValueDigest:    "b149c21602f0c4b98c0fb0c2a9f8b9047da02d4bd734682360a8f9d65bb3f857",
		IdempotencyKey: "secret.sync.github-production:sync-restart", Sealed: ciphertext,
	})
	apply(projections.EventSecretSyncDelivered, projections.SecretSyncDelivered{ID: "sync-restart", Attempts: 1})
	apply(projections.EventSecretSyncQueued, projections.SecretSyncQueued{
		ID: "sync-restart-newer", SecretName: "production/database", SecretVersion: 5,
		Target: "github-production", RemoteKey: "ANOTHER_DATABASE_URL",
		ValueDigest:    "c249c21602f0c4b98c0fb0c2a9f8b9047da02d4bd734682360a8f9d65bb3f858",
		IdempotencyKey: "secret.sync.github-production:sync-restart-newer", Sealed: []byte("newer-ciphertext"),
	})

	assertSecretIntegrationProjection(t, s)
	beforeOlder, err := s.GetSecretSyncJob(ctx, tenantA, "sync-restart")
	if err != nil {
		t.Fatal(err)
	}
	beforeNewer, err := s.GetSecretSyncJob(ctx, tenantA, "sync-restart-newer")
	if err != nil {
		t.Fatal(err)
	}
	// A successful high-volume sync must remain eligible for ordinary outbox GC.
	// Its terminal job and immutable events are enough to rebuild it safely.
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox
		    SET status = 'delivered', delivered_at = $3
		  WHERE tenant_id = $1 AND id = $2`,
		tenantA, beforeOlder.OutboxID, time.Now().UTC().Add(-72*time.Hour)); err != nil {
		t.Fatalf("finalize delivered secret-sync fixture: %v", err)
	}
	if reclaimed, err := outboxgc.New(s, time.Hour).Sweep(ctx); err != nil || reclaimed != 1 {
		t.Fatalf("purge delivered secret-sync outbox=(%d,%v), want (1,nil)", reclaimed, err)
	}
	var purged int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND id = $2`,
		tenantA, beforeOlder.OutboxID).Scan(&purged); err != nil {
		t.Fatal(err)
	}
	if purged != 0 {
		t.Fatalf("delivered secret-sync outbox survived GC: rows=%d", purged)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	assertSecretIntegrationProjection(t, s)
	afterOlder, err := s.GetSecretSyncJob(ctx, tenantA, "sync-restart")
	if err != nil {
		t.Fatal(err)
	}
	afterNewer, err := s.GetSecretSyncJob(ctx, tenantA, "sync-restart-newer")
	if err != nil {
		t.Fatal(err)
	}
	if beforeOlder.TargetOrder != afterOlder.TargetOrder || beforeNewer.TargetOrder != afterNewer.TargetOrder || afterOlder.TargetOrder >= afterNewer.TargetOrder {
		t.Fatalf("full replay target order before=(%d,%d) after=(%d,%d)",
			beforeOlder.TargetOrder, beforeNewer.TargetOrder, afterOlder.TargetOrder, afterNewer.TargetOrder)
	}
	// Rebuild is one PostgreSQL transaction and publishes the final checkpoint only
	// at commit. The recreated older cleanup row is therefore already terminal when
	// a worker can see it: it performs zero receiver I/O, while the pending successor
	// still progresses.
	var receiverCalls []string
	handler := orchestrator.HandlerFunc(func(_ context.Context, message orchestrator.Message) error {
		var command struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(message.Payload, &command); err != nil {
			return err
		}
		job, err := s.GetSecretSyncJob(ctx, message.TenantID, command.ID)
		if err != nil {
			return err
		}
		if job.Status != store.SecretSyncJobPending {
			return nil
		}
		receiverCalls = append(receiverCalls, command.ID)
		return applyDeliveredSecretSyncFixture(ctx, s, message.TenantID, command.ID, message.Attempts, time.Now().UTC())
	})
	if n, err := orchestrator.NewOutbox(s).DispatchScoped(ctx, handler,
		orchestrator.DestinationScope{IncludePrefixes: []string{"secret.sync."}}); err != nil || n != 2 {
		t.Fatalf("post-rebuild secret-sync dispatch=(%d,%v), want two cleanup/progress rows", n, err)
	}
	if len(receiverCalls) != 1 || receiverCalls[0] != afterNewer.ID {
		t.Fatalf("post-GC rebuild receiver calls=%v, want only pending successor %s", receiverCalls, afterNewer.ID)
	}

	var payload []byte
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = 'secret.sync.github-production'`, tenantA).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte("actual-secret-value")) || !bytes.Contains(payload, []byte(`"sealed"`)) {
		t.Fatalf("secret-sync outbox payload is not ciphertext-only: %q", payload)
	}
}

func TestDynamicSecretIssuanceFailureRetainsOriginalTenantEpochAUD108(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	projector := projections.New(s)
	apply := func(event events.Event) {
		t.Helper()
		if err := projector.Apply(ctx, event); err != nil {
			t.Fatalf("apply %s: %v", event.Type, err)
		}
	}
	pending := func(name string) events.Event {
		t.Helper()
		return appendJSONEvent(t, log, projections.EventDynamicSecretLeasePending, tenantA,
			projections.DynamicSecretLeasePending{
				ID: "lease-reused-across-registration", IdempotencyKey: "issue-" + name,
				RequestBinding: "sha256:" + name, Provider: "postgres-production", Role: "reader",
				ExpiresAt: time.Now().UTC().Add(time.Hour), HardExpiresAt: time.Now().UTC().Add(2 * time.Hour),
			})
	}

	apply(appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA,
		map[string]string{"name": "old registration"}))
	apply(pending("old"))
	oldEpoch, err := s.DynamicSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	failureData, err := json.Marshal(projections.DynamicSecretLeaseIssuanceFailure{
		TenantEpoch: oldEpoch, ID: "lease-reused-across-registration", Error: "old provider failed",
	})
	if err != nil {
		t.Fatal(err)
	}
	oldFailure, err := log.Append(ctx, events.Event{
		ID:   store.DynamicSecretEventID(tenantA, oldEpoch, "provider-issue-failed", "lease-reused-across-registration"),
		Type: projections.EventDynamicSecretLeaseIssuanceFailed, TenantID: tenantA,
		SchemaVersion: projections.DynamicSecretIssuanceFailureEventSchemaVersion,
		Data:          failureData,
	})
	if err != nil {
		t.Fatal(err)
	}

	apply(appendJSONEvent(t, log, projections.EventTenantOffboarded, tenantA,
		map[string]int{"rows_deleted": 1}))
	newRegistration := appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA,
		map[string]string{"name": "new registration"})
	apply(newRegistration)
	newPending := pending("new")
	apply(newPending)
	newEpoch, err := s.DynamicSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if newEpoch == oldEpoch {
		t.Fatalf("tenant epoch did not rotate: %q", newEpoch)
	}
	beforeFailure, err := s.GetDynamicSecretLease(ctx, tenantA, "lease-reused-across-registration")
	if err != nil {
		registered, tenantErr := s.GetTenant(ctx, tenantA)
		t.Fatalf("load new-registration pending lease before stale failure: %v (registration seq=%d, pending seq=%d, projected tenant=%+v tenant_err=%v)",
			err, newRegistration.Sequence, newPending.Sequence, registered, tenantErr)
	}
	if beforeFailure.State != store.DynamicSecretLeasePending || beforeFailure.TenantEpoch != newEpoch {
		t.Fatalf("new-registration pending lease = %+v", beforeFailure)
	}

	// Deliver the retained old event after the new registration has recreated the
	// same public lease ID. Its immutable old epoch must make it inert.
	apply(oldFailure)
	lease, err := s.GetDynamicSecretLease(ctx, tenantA, "lease-reused-across-registration")
	if err != nil {
		t.Fatal(err)
	}
	if lease.State != store.DynamicSecretLeasePending || lease.TenantEpoch != newEpoch ||
		lease.IdempotencyKey != "issue-new" || lease.LastError != "" {
		t.Fatalf("old failure changed new registration lease: %+v", lease)
	}
}

func assertSecretIntegrationProjection(t *testing.T, s *store.Store) {
	t.Helper()
	ctx := context.Background()
	lease, err := s.GetDynamicSecretLease(ctx, tenantA, "lease-restart")
	if err != nil {
		t.Fatal(err)
	}
	if lease.State != store.DynamicSecretLeaseRevoked || lease.RevocationStatus != store.DynamicSecretRevocationPending || lease.BackendRef != "trstctl_reader_restart" || len(lease.SealedPreparation) != 0 {
		t.Fatalf("lease projection = %+v", lease)
	}
	job, err := s.GetSecretSyncJob(ctx, tenantA, "sync-restart")
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != store.SecretSyncJobDelivered || job.Attempts != 1 || job.OutboxID == 0 {
		t.Fatalf("sync job projection = %+v", job)
	}
	var issues, revocations, syncs int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE destination = 'dynsecret.issue'),
		        count(*) FILTER (WHERE destination = 'dynsecret.revoke'),
		        count(*) FILTER (WHERE destination = 'secret.sync.github-production')
		   FROM outbox WHERE tenant_id = $1`, tenantA).Scan(&issues, &revocations, &syncs); err != nil {
		t.Fatal(err)
	}
	if issues != 1 || revocations != 1 || syncs != 2 {
		t.Fatalf("outbox counts issues=%d revocations=%d syncs=%d, want 1/1/2", issues, revocations, syncs)
	}
}
