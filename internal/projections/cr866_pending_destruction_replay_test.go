// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

type cr866OffboardPolicy struct{ registrationID string }

func (p cr866OffboardPolicy) EventKeyDestructionForOffboard(_ context.Context, e events.Event) (eventprotect.DestructionRequest, bool, error) {
	if e.Type != projections.EventTenantOffboarded {
		return eventprotect.DestructionRequest{}, false, nil
	}
	request := eventprotect.DestructionRequest{
		Ref: eventprotect.KeyRef{TenantID: e.TenantID,
			ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("cr866-key:"+e.TenantID)).String()},
		OperationID:          uuid.NewSHA1(uuid.NameSpaceOID, []byte("cr866-destroy:"+e.ID)).String(),
		RegistrationIdentity: p.registrationID, ActivationEventID: p.registrationID,
		ActivationSequence: 1, CreationDigest: strings.Repeat("a", 64),
		OffboardEventID: e.ID, OffboardSequence: e.Sequence,
		OffboardedAt: e.Time, NotBefore: e.Time.Add(time.Hour),
	}
	return request, true, request.Validate()
}

type cr866Fixture struct {
	store     *store.Store
	log       *events.Log
	projector *projections.Projector
	offboard  events.Event
	neighbor  events.Event
}

func newCR866Fixture(t *testing.T) cr866Fixture {
	t.Helper()
	ctx := t.Context()
	st := newStore(t)
	log := openLog(t)
	registered, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered,
		TenantID: tenantA, Data: tenantRegistered("protected tenant")})
	if err != nil {
		t.Fatal(err)
	}
	policy := cr866OffboardPolicy{registrationID: registered.ID}
	projector := projections.New(st, projections.WithEventProtectionOffboardPolicy(policy))
	if err := projector.Apply(ctx, registered); err != nil {
		t.Fatal(err)
	}
	owner, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated,
		TenantID: tenantA, Data: ownerCreated(uuid.NewString(), "old protected owner")})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, owner); err != nil {
		t.Fatal(err)
	}
	offboard, err := log.Append(ctx, events.Event{Type: projections.EventTenantOffboarded,
		TenantID: tenantA, Data: []byte(`{"rows_deleted":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, offboard); err != nil {
		t.Fatalf("inline protected offboard: %v", err)
	}
	if _, err := st.GetTenant(ctx, tenantA); !store.IsNotFound(err) {
		t.Fatalf("inline offboard retained registration: %v", err)
	}
	neighbor, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered,
		TenantID: tenantB, Data: tenantRegistered("healthy neighbor")})
	if err != nil {
		t.Fatal(err)
	}
	return cr866Fixture{store: st, log: log, projector: projector, offboard: offboard, neighbor: neighbor}
}

func (f cr866Fixture) assertOffboardedAndNeighbor(t *testing.T) {
	t.Helper()
	ctx := t.Context()
	st := f.store
	if _, err := st.GetTenant(ctx, tenantA); !store.IsNotFound(err) {
		t.Errorf("catch-up resurrected offboarded registration: %v", err)
	}
	if got := ownerCount(t, st, tenantA); got != 0 {
		t.Errorf("catch-up resurrected %d old protected owners", got)
	}
	if err := st.RequireLiveTenantService(ctx, tenantA); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Errorf("offboarded tenant became serviceable: %v", err)
	}
	if _, err := st.GetTenant(ctx, tenantB); err != nil {
		t.Errorf("healthy neighbor at sequence %d did not project: %v", f.neighbor.Sequence, err)
	}
	var pending int
	if err := st.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox
		WHERE tenant_id=$1 AND destination=$2`, tenantA, store.EventKeyDestructionDestination).Scan(&pending); err != nil || pending != 1 {
		t.Errorf("pending destruction row changed during replay: rows=%d err=%v", pending, err)
	}
}

// CR-866: inline protected offboard can get ahead of the durable consumer.
// Catch-up must not recreate old rows or effects and block unrelated tenants.
func TestCR866PendingDestructionCatchUpDoesNotResurrectOffboardedTenant(t *testing.T) {
	f := newCR866Fixture(t)
	if err := f.projector.ProjectCatchUp(t.Context(), f.log); err != nil {
		t.Fatalf("protected offboard replay blocked shared catch-up at %d: %v", f.offboard.Sequence, err)
	}
	f.assertOffboardedAndNeighbor(t)
}

// Use the actual source policy and independent file-key authority, not just the
// minimal request stub above, to cover opt-in and pending receiver custody.
func TestCR866ProtectedOptInCatchUpKeepsPendingDestruction(t *testing.T) {
	f := newEventProtectionOffboardFixture(t)
	ctx := t.Context()
	if _, err := f.record(ctx, events.Event{Type: projections.EventOwnerCreated,
		TenantID: tenantA, Data: ownerCreated(uuid.NewString(), "erased owner")}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.record(ctx, events.Event{ID: projections.TenantOffboardEventID(tenantA, f.registration.ID),
		Type: projections.EventTenantOffboarded, TenantID: tenantA,
		Data: []byte(`{"rows_deleted":0}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.record(ctx, events.Event{Type: projections.EventOwnerCreated,
		TenantID: tenantB, Data: ownerCreated(uuid.NewString(), "neighbor owner")}); err != nil {
		t.Fatal(err)
	}
	if err := f.projector.ProjectCatchUp(ctx, f.log); err != nil {
		t.Fatalf("real protected opt-in blocked shared catch-up: %v", err)
	}
	if got := ownerCount(t, f.store, tenantA); got != 0 {
		t.Errorf("protected owner resurrected: %d", got)
	}
	if got := ownerCount(t, f.store, tenantB); got != 1 {
		t.Errorf("healthy neighbor owner missing: %d", got)
	}
	var pending int
	if err := f.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox
		WHERE tenant_id=$1 AND destination=$2`, tenantA, store.EventKeyDestructionDestination).Scan(&pending); err != nil || pending != 1 {
		t.Errorf("independent destruction intent changed: rows=%d err=%v", pending, err)
	}
}

func TestCR866PendingDestructionTailAdvancesPastInlineOffboard(t *testing.T) {
	f := newCR866Fixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	worker := projections.NewTailWorker(f.log, f.projector, nil, 0)
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for worker.Applied() < f.neighbor.Sequence {
		select {
		case err := <-done:
			t.Fatalf("protected offboard stopped shared tail at %d: %v", worker.Applied(), err)
		case <-ctx.Done():
			t.Fatalf("tail did not project healthy neighbor: %v", ctx.Err())
		case <-ticker.C:
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("tail did not stop after cancellation")
	}
	f.assertOffboardedAndNeighbor(t)
}

func TestCR866SnapshotTailPreservesPendingDestructionAndErasesOldRows(t *testing.T) {
	ctx := t.Context()
	st := newStore(t)
	log := openLog(t)
	// The snapshot predates this protected registration, so its generation
	// remains complete when the later offboard deletes tenant A's snapshots.
	registeredNeighbor, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered,
		TenantID: tenantB, Data: tenantRegistered("snapshot healthy neighbor")})
	if err != nil {
		t.Fatal(err)
	}
	p := projections.New(st)
	if err := p.Apply(ctx, registeredNeighbor); err != nil {
		t.Fatal(err)
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	t.Log("captured neighbor-only snapshot")
	registered, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered,
		TenantID: tenantA, Data: tenantRegistered("snapshot protected")})
	if err != nil {
		t.Fatal(err)
	}
	p = projections.New(st, projections.WithEventProtectionOffboardPolicy(cr866OffboardPolicy{registrationID: registered.ID}))
	if err := p.Apply(ctx, registered); err != nil {
		t.Fatal(err)
	}
	owner, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated,
		TenantID: tenantA, Data: ownerCreated(uuid.NewString(), "old snapshot owner")})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(ctx, owner); err != nil {
		t.Fatal(err)
	}
	offboard, err := log.Append(ctx, events.Event{Type: projections.EventTenantOffboarded,
		TenantID: tenantA, Data: []byte(`{"rows_deleted":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(ctx, offboard); err != nil {
		t.Fatal(err)
	}
	t.Log("projected protected offboard inline")
	neighbor, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated,
		TenantID: tenantB, Data: ownerCreated(uuid.NewString(), "snapshot tail neighbor")})
	if err != nil {
		t.Fatal(err)
	}
	truncateReadModelAndCheckpoint(t, st)
	t.Log("cleared test read model and checkpoint")
	restored, err := p.RestoreFromSnapshot(ctx, log)
	if err != nil || !restored {
		t.Fatalf("snapshot-tail protected offboard restore: restored=%v err=%v", restored, err)
	}
	(cr866Fixture{store: st, log: log, projector: p, offboard: offboard, neighbor: neighbor}).assertOffboardedAndNeighbor(t)
	if got := ownerCount(t, st, tenantB); got != 1 {
		t.Errorf("snapshot tail did not project neighbor owner: %d", got)
	}
}

func TestCR866PendingDestructionResidueStillFailsClosedAndRebuildRecovers(t *testing.T) {
	f := newCR866Fixture(t)
	ctx := t.Context()
	var pendingID int64
	var pendingPayload []byte
	var pendingStatus, pendingKey string
	if err := f.store.SystemPool().QueryRow(ctx, `SELECT id,payload,status,idempotency_key FROM outbox
		WHERE tenant_id=$1 AND destination=$2`, tenantA, store.EventKeyDestructionDestination).
		Scan(&pendingID, &pendingPayload, &pendingStatus, &pendingKey); err != nil {
		t.Fatal(err)
	}
	if err := f.store.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "unexpected later residue"}); err != nil {
		t.Fatal(err)
	}
	if err := f.projector.ProjectCatchUp(ctx, f.log); !errors.Is(err, store.ErrPendingEventKeyDestructionResidue) || !strings.Contains(err.Error(), "tenants: 1") {
		t.Fatalf("pending intent silently erased unrelated residue: %v", err)
	}
	if _, err := f.store.GetTenant(ctx, tenantA); err != nil {
		t.Fatalf("failed strict retry removed unexpected registration: %v", err)
	}
	if err := f.projector.Rebuild(ctx, f.log); err != nil {
		t.Fatalf("full read-model rebuild did not recover shared replay: %v", err)
	}
	f.assertOffboardedAndNeighbor(t)
	var restoredID int64
	var restoredPayload []byte
	var restoredStatus, restoredKey string
	if err := f.store.SystemPool().QueryRow(ctx, `SELECT id,payload,status,idempotency_key FROM outbox
		WHERE tenant_id=$1 AND destination=$2`, tenantA, store.EventKeyDestructionDestination).
		Scan(&restoredID, &restoredPayload, &restoredStatus, &restoredKey); err != nil {
		t.Fatal(err)
	}
	if restoredID != pendingID || !bytes.Equal(restoredPayload, pendingPayload) ||
		restoredStatus != pendingStatus || restoredKey != pendingKey {
		t.Fatal("rebuild replaced or re-dispatched the original pending destruction")
	}
}

func TestCR866ForgedPendingDestructionWitnessCannotSuppressReplay(t *testing.T) {
	f := newCR866Fixture(t)
	ctx := t.Context()
	var original []byte
	if err := f.store.SystemPool().QueryRow(ctx, `SELECT payload FROM outbox
		WHERE tenant_id=$1 AND destination=$2`, tenantA, store.EventKeyDestructionDestination).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if len(original) == 0 || original[len(original)-1] != '}' {
		t.Fatal("test destruction payload was not canonical JSON")
	}
	forged := append(append([]byte(nil), original[:len(original)-1]...), []byte(`,"forged":true}`)...)
	if _, err := f.store.SystemPool().Exec(ctx, `UPDATE outbox SET payload=$3
		WHERE tenant_id=$1 AND destination=$2`, tenantA, store.EventKeyDestructionDestination, forged); err != nil {
		t.Fatal(err)
	}
	if skip, err := f.store.PendingEventKeyDestructionAfter(ctx, tenantA, f.offboard.Sequence-1); err == nil || skip {
		t.Fatalf("noncanonical outbox payload suppressed source replay: skip=%v err=%v", skip, err)
	}
	if skip, err := f.store.PendingEventKeyDestructionAfter(ctx, tenantB, f.offboard.Sequence-1); err != nil || skip {
		t.Fatalf("tenant A's forged row affected healthy neighbor: skip=%v err=%v", skip, err)
	}
}
