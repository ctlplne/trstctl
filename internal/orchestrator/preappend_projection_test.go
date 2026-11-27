// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestPreparedEventSerializesSharedIdentityAcrossTenants(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	data, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: uuid.NewString(), Name: "Workload notifications", ScopeKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	orch := orchestrator.NewOrchestrator(log, st, nil)
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		tenantID := uuid.NewString()
		go func() {
			<-start
			_, err := orchestrator.EmitPreparedForTest(t.Context(), orch, events.Event{
				Type: projections.EventNotificationRoutingPolicyUpserted, TenantID: tenantID, Data: data,
			})
			results <- err
		}()
	}
	close(start)
	succeeded := 0
	for range 2 {
		err := <-results
		if err == nil {
			succeeded++
		} else if !errors.Is(err, store.ErrNotificationRoutingIdentityConflict) {
			t.Fatalf("unexpected policy admission error: %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("accepted policies = %d, want one", succeeded)
	}
	sequence, err := log.LastSequence(t.Context())
	if err != nil || sequence != 1 {
		t.Fatalf("retained sequence = %d, err=%v, want 1", sequence, err)
	}
}

func TestPreparedEventChecksProjectionBeforePublication(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	policyID, firstTenant, secondTenant := uuid.NewString(), uuid.NewString(), uuid.NewString()
	data, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: policyID, Name: "Workload notifications", ScopeKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	orch := orchestrator.NewOrchestrator(log, st, nil)
	first := events.Event{ID: uuid.NewString(), Type: projections.EventNotificationRoutingPolicyUpserted,
		TenantID: firstTenant, Data: data}
	accepted, err := orchestrator.EmitPreparedForTest(ctx, orch, first)
	if err != nil {
		t.Fatalf("first policy: %v", err)
	}
	if repeated, err := orchestrator.EmitPreparedForTest(ctx, orch, first); err != nil || repeated.Sequence != accepted.Sequence {
		t.Fatalf("exact retry sequence=%d err=%v, want %d", repeated.Sequence, err, accepted.Sequence)
	}
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orchestrator.EmitPreparedForTest(ctx, orch, events.Event{Type: projections.EventNotificationRoutingPolicyUpserted,
		TenantID: secondTenant, Data: data}); !errors.Is(err, store.ErrNotificationRoutingIdentityConflict) {
		t.Fatalf("second policy error = %v, want tenant-owned identity refusal", err)
	}
	after, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("rejected policy advanced event sequence from %d to %d", before, after)
	}
}
