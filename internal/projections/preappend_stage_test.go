// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestStagedProjectionReceiptBindsExactEventAndCommit(t *testing.T) {
	st := newStore(t)
	projector := projections.New(st)
	ctx := context.Background()
	policyID := uuid.NewString()
	data, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: policyID, Name: "Primary route", ScopeKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{ID: uuid.NewString(), Type: projections.EventNotificationRoutingPolicyUpserted,
		TenantID: tenantA, Sequence: 1, Time: time.Now().UTC(), SchemaVersion: 1, Data: data}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := projector.StagePreappendTx(ctx, tx, event); err != nil {
			return err
		}
		return projector.ApplyTx(ctx, tx, event)
	}); err != nil {
		t.Fatalf("stage and apply the same event: %v", err)
	}
	policy, err := st.GetNotificationRoutingPolicy(ctx, tenantA, policyID)
	if err != nil || policy.Name != "Primary route" {
		t.Fatalf("committed policy: value=%+v err=%v", policy, err)
	}
	changedData, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: policyID, Name: "Changed route", ScopeKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	changed := event
	changed.Data = changedData
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return projector.ApplyTx(ctx, tx, changed)
	}); !errors.Is(err, store.ErrProjectionStagedEventMismatch) {
		t.Fatalf("changed event with a committed receipt: %v", err)
	}
	policy, err = st.GetNotificationRoutingPolicy(ctx, tenantA, policyID)
	if err != nil || policy.Name != "Primary route" {
		t.Fatalf("policy after refused changed event: value=%+v err=%v", policy, err)
	}
}

func TestStagedProjectionRollbackLeavesNoReceiptOrReadState(t *testing.T) {
	st := newStore(t)
	projector := projections.New(st)
	ctx := context.Background()
	policyID := uuid.NewString()
	data, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: policyID, Name: "Rollback route", ScopeKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{ID: uuid.NewString(), Type: projections.EventNotificationRoutingPolicyUpserted,
		TenantID: tenantA, Sequence: 1, Time: time.Now().UTC(), SchemaVersion: 1, Data: data}
	stop := errors.New("rollback staged projection")
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := projector.StagePreappendTx(ctx, tx, event); err != nil {
			return err
		}
		return stop
	}); !errors.Is(err, stop) {
		t.Fatalf("rollback stage: %v", err)
	}
	if _, err := st.GetNotificationRoutingPolicy(ctx, tenantA, policyID); !store.IsNotFound(err) {
		t.Fatalf("read state after rollback: %v", err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return projector.ApplyTx(ctx, tx, event)
	}); err != nil {
		t.Fatalf("project event after rollback: %v", err)
	}
	policy, err := st.GetNotificationRoutingPolicy(ctx, tenantA, policyID)
	if err != nil || policy.Name != "Rollback route" {
		t.Fatalf("read state after replay: value=%+v err=%v", policy, err)
	}
}

func TestStagedProjectionReplayWaitsForCommittedReceipt(t *testing.T) {
	st := newStore(t)
	projector := projections.New(st)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	policyID := uuid.NewString()
	data, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: policyID, Name: "Committed route", ScopeKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{ID: uuid.NewString(), Type: projections.EventNotificationRoutingPolicyUpserted,
		TenantID: tenantA, Sequence: 1, Time: time.Now().UTC(), SchemaVersion: 1, Data: data}
	changedData, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: policyID, Name: "Different route", ScopeKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	changed := event
	changed.Data = changedData
	staged := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	stageDone := make(chan error, 1)
	go func() {
		stageDone <- st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if err := projector.StagePreappendTx(ctx, tx, event); err != nil {
				return err
			}
			close(staged)
			<-release
			return nil
		})
	}()
	select {
	case <-staged:
	case err := <-stageDone:
		t.Fatalf("stage before replay: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	replayDone := make(chan error, 1)
	go func() {
		replayDone <- st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return projector.ApplyTx(ctx, tx, changed)
		})
	}()
	select {
	case err := <-replayDone:
		t.Fatalf("replay completed before staged transaction: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-stageDone; err != nil {
		t.Fatalf("commit staged projection: %v", err)
	}
	if err := <-replayDone; !errors.Is(err, store.ErrProjectionStagedEventMismatch) {
		t.Fatalf("replay checked committed event binding: %v", err)
	}
}

func TestStagedProjectionRequiresProtectedReceiptForSealedEvent(t *testing.T) {
	st := newStore(t)
	projector := projections.New(st)
	ctx := context.Background()
	event := events.Event{ID: uuid.NewString(), Type: "secret.created", TenantID: tenantA,
		Sequence: 1, Time: time.Now().UTC(), SchemaVersion: 1, Data: []byte(`{}`)}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := projector.StagePreappendTx(ctx, tx, event); err == nil {
			return errors.New("protected event entered an unkeyed receipt")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStagedProjectionReceiptExtendsMatchingLegacyReceipt(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	eventID := uuid.NewString()
	digest := bytes.Repeat([]byte{0x41}, 32)
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := st.RecordProjectionAppliedEventReceiptTx(ctx, tx, tenantA, eventID, 12); err != nil {
			return err
		}
		if err := st.RecordStagedProjectionEventReceiptTx(ctx, tx, tenantA, eventID, 12, digest); err != nil {
			return err
		}
		stored, found, err := st.StagedProjectionEventReceiptTx(ctx, tx, tenantA, eventID, 12)
		if err != nil || !found || !bytes.Equal(stored, digest) {
			return errors.New("matching legacy receipt did not retain its staged digest")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.RecordStagedProjectionEventReceiptTx(ctx, tx, tenantA, eventID, 13, digest)
	}); !errors.Is(err, store.ErrProjectionStagedEventMismatch) {
		t.Fatalf("different sequence changed the receipt: %v", err)
	}
}
