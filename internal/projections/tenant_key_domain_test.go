// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func tenantKeyDomainSnapshot(state, operationStatus string, completed int64) projections.TenantKeyDomainSnapshot {
	operationID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	return projections.TenantKeyDomainSnapshot{
		DomainID:               "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		Generation:             1,
		ProtectionMode:         store.TenantKeyProtectionTenantDomain,
		State:                  state,
		WrapperKind:            "local_file",
		WrapperID:              "tenant-wrapper",
		WrappedDomainKEK:       []byte{0x00, 0x7f, 0x80, 0xff},
		OperationID:            &operationID,
		OperationKind:          store.TenantKeyOperationMigrate,
		OperationStatus:        operationStatus,
		MigrationStage:         "jetstream_hot_history",
		ProgressCompleted:      completed,
		ProgressTotal:          10,
		ProgressCursor:         `{"sequence":7}`,
		Retryable:              true,
		LegacyHistoryExposure:  store.TenantKeyLegacyHotHistoryPending,
		TransitionEvidenceRefs: []string{"audit://tenant-domain/progress"},
		CreatedAt:              time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC),
	}
}

func tenantKeyDomainEvent(t *testing.T, typ string, seq uint64, snapshot projections.TenantKeyDomainSnapshot) events.Event {
	t.Helper()
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return events.Event{
		ID:            "event-" + typ,
		Type:          typ,
		TenantID:      tenantA,
		Time:          time.Date(2026, 7, 31, 1, 2, int(seq), 0, time.UTC),
		Sequence:      seq,
		SchemaVersion: 1,
		Data:          data,
		Actor:         &events.Actor{Subject: "operator@example.test"},
	}
}

// TestTenantKeyDomainProjectionIsReplayableAndMonotonic proves every transition
// carries a complete record: a progress event alone updates all state needed for
// recovery, wrapped key bytes survive JSON/event projection, and a lagging inline
// replay cannot regress a newer transition.
func TestTenantKeyDomainProjectionIsReplayableAndMonotonic(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	p := projections.New(s)

	start := tenantKeyDomainSnapshot(store.TenantKeyDomainStateMigrating, store.TenantKeyOperationRunning, 0)
	if err := p.Apply(ctx, tenantKeyDomainEvent(t, projections.EventTenantKeyDomainMigrationStarted, 10, start)); err != nil {
		t.Fatalf("apply migration start: %v", err)
	}
	progress := tenantKeyDomainSnapshot(store.TenantKeyDomainStatePartial, store.TenantKeyOperationRunning, 7)
	if err := p.Apply(ctx, tenantKeyDomainEvent(t, projections.EventTenantKeyDomainMigrationProgressed, 11, progress)); err != nil {
		t.Fatalf("apply migration progress: %v", err)
	}
	// The durable tail may replay the older start after the command side has already
	// projected progress. last_transition_sequence makes that stale event a no-op.
	if err := p.Apply(ctx, tenantKeyDomainEvent(t, projections.EventTenantKeyDomainMigrationStarted, 10, start)); err != nil {
		t.Fatalf("replay stale migration start: %v", err)
	}

	got, err := s.GetTenantKeyDomain(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != store.TenantKeyDomainStatePartial || got.ProgressCompleted != 7 {
		t.Fatalf("projected state/progress = %s/%d, want partial/7", got.State, got.ProgressCompleted)
	}
	if got.LastTransitionEventID != "event-"+projections.EventTenantKeyDomainMigrationProgressed ||
		got.LastTransitionActor != "operator@example.test" ||
		got.LastTransitionSequence != 11 {
		t.Fatalf("last transition evidence = %+v", got)
	}
	if !bytes.Equal(got.WrappedDomainKEK, progress.WrappedDomainKEK) {
		t.Fatalf("wrapped KEK = %x, want %x", got.WrappedDomainKEK, progress.WrappedDomainKEK)
	}

	// A corrupt duplicate carrying the same stream sequence must also be a no-op.
	// JetStream sequences are unique; accepting different bytes at an equal
	// sequence would let a replay overwrite already-projected custody state.
	equalSequence := progress
	equalSequence.State = store.TenantKeyDomainStateCorrupt
	equalSequence.OperationStatus = store.TenantKeyOperationFailed
	equalSequence.LastErrorCode = "synthetic_equal_sequence"
	equalSequence.LastError = "must not replace the projected event"
	if err := p.Apply(ctx, tenantKeyDomainEvent(
		t,
		projections.EventTenantKeyDomainMigrationFailed,
		11,
		equalSequence,
	)); err != nil {
		t.Fatalf("apply equal-sequence replay: %v", err)
	}
	unchanged, err := s.GetTenantKeyDomain(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.State != store.TenantKeyDomainStatePartial ||
		unchanged.LastTransitionType != projections.EventTenantKeyDomainMigrationProgressed {
		t.Fatalf("equal-sequence replay overwrote projected custody state: %+v", unchanged)
	}
}

// TestTenantKeyDomainSealRequestProjectsDurableOutboxAndRepairsReplay is the
// crash wall for the served seal protocol. The immutable request and its
// tenant-scoped worker command must project in one PostgreSQL transaction. If a
// crash or operator repair removes only the derived outbox row, replaying the
// exact same event must reconstruct the same command without inventing another
// lifecycle operation.
func TestTenantKeyDomainSealRequestProjectsDurableOutboxAndRepairsReplay(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	p := projections.New(s)

	migrated := tenantKeyDomainSnapshot(
		store.TenantKeyDomainStatePartial,
		store.TenantKeyOperationCompleted,
		10,
	)
	migrated.ProgressCompleted = migrated.ProgressTotal
	migrated.LegacyHistoryExposure = store.TenantKeyLegacyExternalArchivesPossible
	if err := p.Apply(ctx, tenantKeyDomainEvent(
		t,
		projections.EventTenantKeyDomainMigrationCompleted,
		10,
		migrated,
	)); err != nil {
		t.Fatalf("seed migrated domain: %v", err)
	}

	operationID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	queued := migrated
	queued.State = store.TenantKeyDomainStateSealQueued
	queued.OperationID = &operationID
	queued.OperationKind = store.TenantKeyOperationSeal
	queued.OperationStatus = store.TenantKeyOperationPending
	queued.SealIdempotencyKey = "operator-seal-key"
	queued.SealRequestBinding = strings.Repeat("a", 64)
	event := tenantKeyDomainEvent(t, projections.EventTenantKeyDomainSealRequested, 11, queued)
	if err := p.Apply(ctx, event); err != nil {
		t.Fatalf("apply seal request: %v", err)
	}
	assertTenantKeyDomainSealOutbox(t, s, tenantA, operationID, queued.SealIdempotencyKey, queued.SealRequestBinding)

	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM outbox
			  WHERE tenant_id = $1 AND idempotency_key = $2`,
			tenantA, store.TenantKeyDomainSealOutboxKey(operationID))
		return err
	}); err != nil {
		t.Fatalf("simulate missing derived seal outbox: %v", err)
	}
	if err := p.Apply(ctx, event); err != nil {
		t.Fatalf("replay seal request: %v", err)
	}
	assertTenantKeyDomainSealOutbox(t, s, tenantA, operationID, queued.SealIdempotencyKey, queued.SealRequestBinding)
}

func assertTenantKeyDomainSealOutbox(
	t *testing.T,
	s *store.Store,
	tenantID, operationID, idempotencyKey, requestBinding string,
) {
	t.Helper()
	var destination, effectLane, outboxKey string
	var payload []byte
	if err := s.WithTenant(context.Background(), tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT destination, effect_lane, idempotency_key, payload
			   FROM outbox
			  WHERE tenant_id = $1 AND idempotency_key = $2`,
			tenantID, store.TenantKeyDomainSealOutboxKey(operationID)).Scan(
			&destination, &effectLane, &outboxKey, &payload,
		)
	}); err != nil {
		t.Fatalf("read projected seal outbox: %v", err)
	}
	if destination != store.TenantKeyDomainSealDestination ||
		effectLane != store.TenantKeyDomainSealEffectLane ||
		outboxKey != store.TenantKeyDomainSealOutboxKey(operationID) {
		t.Fatalf("seal outbox routing = %q/%q/%q", destination, effectLane, outboxKey)
	}
	var command store.TenantKeyDomainSealCommand
	if err := json.Unmarshal(payload, &command); err != nil {
		t.Fatalf("decode seal outbox: %v", err)
	}
	if command.OperationID != operationID || command.IdempotencyKey != idempotencyKey ||
		command.RequestBinding != requestBinding {
		t.Fatalf("seal outbox command = %+v", command)
	}
}

// TestTenantKeyDomainAllLifecycleEventsShareOneSnapshotContract pins the eight
// immutable names and the one deterministic payload shape. Each event is accepted
// by schema validation and projects the exact full snapshot it carries.
func TestTenantKeyDomainAllLifecycleEventsShareOneSnapshotContract(t *testing.T) {
	eventTypes := []string{
		projections.EventTenantKeyDomainMigrationStarted,
		projections.EventTenantKeyDomainMigrationProgressed,
		projections.EventTenantKeyDomainMigrationCompleted,
		projections.EventTenantKeyDomainMigrationFailed,
		projections.EventTenantKeyDomainSealRequested,
		projections.EventTenantKeyDomainSealed,
		projections.EventTenantKeyDomainUnsealRequested,
		projections.EventTenantKeyDomainUnsealed,
	}
	states := []string{
		store.TenantKeyDomainStateMigrating,
		store.TenantKeyDomainStatePartial,
		store.TenantKeyDomainStatePartial,
		store.TenantKeyDomainStateWrapperUnavailable,
		store.TenantKeyDomainStateSealQueued,
		store.TenantKeyDomainStateSealed,
		store.TenantKeyDomainStateUnsealing,
		store.TenantKeyDomainStateUnsealed,
	}
	for i, typ := range eventTypes {
		t.Run(typ, func(t *testing.T) {
			s := newStore(t)
			ctx := context.Background()
			if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
				t.Fatal(err)
			}
			p := projections.New(s)
			if typ != projections.EventTenantKeyDomainMigrationStarted {
				start := tenantKeyDomainSnapshot(
					store.TenantKeyDomainStateMigrating,
					store.TenantKeyOperationRunning,
					0,
				)
				if err := p.Apply(ctx, tenantKeyDomainEvent(
					t,
					projections.EventTenantKeyDomainMigrationStarted,
					1,
					start,
				)); err != nil {
					t.Fatalf("seed migration start: %v", err)
				}
			}
			snapshot := tenantKeyDomainSnapshot(states[i], store.TenantKeyOperationRunning, int64(i))
			snapshot.OperationKind = []string{
				store.TenantKeyOperationMigrate, store.TenantKeyOperationMigrate,
				store.TenantKeyOperationMigrate, store.TenantKeyOperationMigrate,
				store.TenantKeyOperationSeal, store.TenantKeyOperationSeal,
				store.TenantKeyOperationUnseal, store.TenantKeyOperationUnseal,
			}[i]
			if typ == projections.EventTenantKeyDomainMigrationCompleted ||
				typ == projections.EventTenantKeyDomainSealed ||
				typ == projections.EventTenantKeyDomainUnsealed {
				snapshot.OperationStatus = store.TenantKeyOperationCompleted
			}
			if typ == projections.EventTenantKeyDomainMigrationCompleted {
				snapshot.ProgressCompleted = snapshot.ProgressTotal
				snapshot.LegacyHistoryExposure = store.TenantKeyLegacyExternalArchivesPossible
			}
			if typ == projections.EventTenantKeyDomainMigrationFailed {
				snapshot.OperationStatus = store.TenantKeyOperationFailed
				snapshot.LastErrorCode = "wrapper_unavailable"
				snapshot.LastError = "configured tenant wrapper is unavailable"
			}
			if typ == projections.EventTenantKeyDomainSealRequested {
				snapshot.OperationStatus = store.TenantKeyOperationPending
				snapshot.SealIdempotencyKey = "projection-seal-request"
				snapshot.SealRequestBinding = strings.Repeat("c", 64)
			}
			if err := p.Apply(ctx, tenantKeyDomainEvent(t, typ, uint64(i+2), snapshot)); err != nil {
				t.Fatalf("Apply(%s): %v", typ, err)
			}
			got, err := s.GetTenantKeyDomain(ctx, tenantA)
			if err != nil {
				t.Fatal(err)
			}
			if got.State != states[i] || got.LastTransitionType != typ {
				t.Fatalf("projected event = state %q type %q, want %q/%q", got.State, got.LastTransitionType, states[i], typ)
			}
		})
	}
}

// TestTenantKeyDomainRebuildAndSnapshotRecovery proves both supported projection
// recovery paths retain the wrapped KEK and resumable migration fields. First a
// full rebuild derives the row from immutable events; then the versioned snapshot
// restores the same row without replaying those covered events.
func TestTenantKeyDomainRebuildAndSnapshotRecovery(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	if _, err := log.Append(ctx, events.Event{
		Type:     projections.EventTenantRegistered,
		TenantID: tenantA,
		Data:     tenantRegistered("Acme"),
	}); err != nil {
		t.Fatalf("append tenant registration: %v", err)
	}
	start := tenantKeyDomainSnapshot(store.TenantKeyDomainStateMigrating, store.TenantKeyOperationRunning, 0)
	startData, err := json.Marshal(start)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type:     projections.EventTenantKeyDomainMigrationStarted,
		TenantID: tenantA,
		Data:     startData,
	}); err != nil {
		t.Fatalf("append key-domain migration start: %v", err)
	}
	progress := tenantKeyDomainSnapshot(store.TenantKeyDomainStatePartial, store.TenantKeyOperationRunning, 7)
	progressData, err := json.Marshal(progress)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type:     projections.EventTenantKeyDomainMigrationProgressed,
		TenantID: tenantA,
		Data:     progressData,
	}); err != nil {
		t.Fatalf("append key-domain progress: %v", err)
	}

	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild tenant key domain: %v", err)
	}
	rebuilt, err := s.GetTenantKeyDomain(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.ProgressCompleted != 7 || !bytes.Equal(rebuilt.WrappedDomainKEK, progress.WrappedDomainKEK) {
		t.Fatalf("rebuilt key domain = %+v", rebuilt)
	}

	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WriteTenantSnapshot(ctx, tenantA, head); err != nil {
		t.Fatalf("write tenant key-domain snapshot: %v", err)
	}
	if err := s.TruncateReadModel(ctx); err != nil {
		t.Fatalf("truncate read model: %v", err)
	}
	if err := s.RestoreReadModelTx(ctx, func(tx pgx.Tx) error {
		_, err := s.RestoreSnapshotsTx(ctx, tx)
		return err
	}); err != nil {
		t.Fatalf("restore tenant key-domain snapshot: %v", err)
	}
	restored, err := s.GetTenantKeyDomain(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if restored.State != rebuilt.State ||
		restored.ProgressCursor != rebuilt.ProgressCursor ||
		!bytes.Equal(restored.WrappedDomainKEK, rebuilt.WrappedDomainKEK) {
		t.Fatalf("snapshot-restored key domain = %+v, want rebuilt %+v", restored, rebuilt)
	}
}

func TestTenantKeyDomainProjectionRejectsMissingOperationSequenceAndClosureEvidence(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	p := projections.New(s)
	invalidOperationID := "not-a-uuid"

	tests := []struct {
		name    string
		typ     string
		seq     uint64
		change  func(*projections.TenantKeyDomainSnapshot)
		wantErr string
	}{
		{
			name: "missing operation id",
			typ:  projections.EventTenantKeyDomainMigrationStarted,
			seq:  1,
			change: func(snapshot *projections.TenantKeyDomainSnapshot) {
				snapshot.OperationID = nil
			},
			wantErr: "operation_id UUID",
		},
		{
			name: "invalid operation id",
			typ:  projections.EventTenantKeyDomainMigrationStarted,
			seq:  1,
			change: func(snapshot *projections.TenantKeyDomainSnapshot) {
				snapshot.OperationID = &invalidOperationID
			},
			wantErr: "valid operation_id UUID",
		},
		{
			name:    "missing stream sequence",
			typ:     projections.EventTenantKeyDomainMigrationStarted,
			seq:     0,
			change:  func(*projections.TenantKeyDomainSnapshot) {},
			wantErr: "positive stream-sequence",
		},
		{
			name: "independence claim without evidence",
			typ:  projections.EventTenantKeyDomainMigrationCompleted,
			seq:  1,
			change: func(snapshot *projections.TenantKeyDomainSnapshot) {
				snapshot.State = store.TenantKeyDomainStateUnsealed
				snapshot.OperationStatus = store.TenantKeyOperationCompleted
				snapshot.ProgressCompleted = snapshot.ProgressTotal
				snapshot.LegacyHistoryExposure = store.TenantKeyLegacyNone
				snapshot.TransitionEvidenceRefs = []string{"   "}
			},
			wantErr: "requires evidence before clearing legacy-history exposure",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := tenantKeyDomainSnapshot(
				store.TenantKeyDomainStateMigrating,
				store.TenantKeyOperationRunning,
				0,
			)
			test.change(&snapshot)
			err := p.Apply(ctx, tenantKeyDomainEvent(t, test.typ, test.seq, snapshot))
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Apply error = %v, want %q", err, test.wantErr)
			}
		})
	}

	completed := tenantKeyDomainSnapshot(
		store.TenantKeyDomainStateUnsealed,
		store.TenantKeyOperationCompleted,
		10,
	)
	completed.LegacyHistoryExposure = store.TenantKeyLegacyNone
	completed.TransitionEvidenceRefs = []string{"backup://tenant-a/reprotected"}
	if err := p.Apply(ctx, tenantKeyDomainEvent(
		t,
		projections.EventTenantKeyDomainMigrationCompleted,
		1,
		completed,
	)); err != nil {
		t.Fatalf("migration completion with evidence: %v", err)
	}
}

func TestTenantKeyDomainProjectionCannotEraseLegacyExposureOnLaterTransitions(t *testing.T) {
	tests := []struct {
		typ    string
		state  string
		kind   string
		status string
	}{
		{projections.EventTenantKeyDomainMigrationProgressed, store.TenantKeyDomainStatePartial, store.TenantKeyOperationMigrate, store.TenantKeyOperationRunning},
		{projections.EventTenantKeyDomainMigrationFailed, store.TenantKeyDomainStatePartial, store.TenantKeyOperationMigrate, store.TenantKeyOperationFailed},
		{projections.EventTenantKeyDomainSealRequested, store.TenantKeyDomainStateSealQueued, store.TenantKeyOperationSeal, store.TenantKeyOperationPending},
		{projections.EventTenantKeyDomainSealed, store.TenantKeyDomainStateSealed, store.TenantKeyOperationSeal, store.TenantKeyOperationCompleted},
		{projections.EventTenantKeyDomainUnsealRequested, store.TenantKeyDomainStateUnsealing, store.TenantKeyOperationUnseal, store.TenantKeyOperationRunning},
		{projections.EventTenantKeyDomainUnsealed, store.TenantKeyDomainStateUnsealed, store.TenantKeyOperationUnseal, store.TenantKeyOperationCompleted},
	}
	for _, test := range tests {
		t.Run(test.typ, func(t *testing.T) {
			s := newStore(t)
			ctx := context.Background()
			if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
				t.Fatal(err)
			}
			p := projections.New(s)
			start := tenantKeyDomainSnapshot(
				store.TenantKeyDomainStateMigrating,
				store.TenantKeyOperationRunning,
				0,
			)
			if err := p.Apply(ctx, tenantKeyDomainEvent(
				t,
				projections.EventTenantKeyDomainMigrationStarted,
				10,
				start,
			)); err != nil {
				t.Fatalf("apply migration start: %v", err)
			}

			next := tenantKeyDomainSnapshot(test.state, test.status, 1)
			next.OperationKind = test.kind
			next.LegacyHistoryExposure = store.TenantKeyLegacyExternalArchivesPossible
			if test.typ == projections.EventTenantKeyDomainSealRequested {
				next.SealIdempotencyKey = "projection-exposure-seal"
				next.SealRequestBinding = strings.Repeat("d", 64)
			}
			if test.typ == projections.EventTenantKeyDomainMigrationFailed {
				next.LastErrorCode = "wrapper_unavailable"
				next.LastError = "configured tenant wrapper is unavailable"
			}
			err := p.Apply(ctx, tenantKeyDomainEvent(t, test.typ, 11, next))
			if err == nil || !strings.Contains(err.Error(), "cannot reduce legacy-history exposure") {
				t.Fatalf("Apply error = %v, want exposure downgrade rejection", err)
			}

			got, err := s.GetTenantKeyDomain(ctx, tenantA)
			if err != nil {
				t.Fatal(err)
			}
			if got.LegacyHistoryExposure != store.TenantKeyLegacyHotHistoryPending ||
				got.LastTransitionSequence != 10 {
				t.Fatalf("rejected transition changed row: exposure=%q sequence=%d",
					got.LegacyHistoryExposure, got.LastTransitionSequence)
			}
		})
	}
}
