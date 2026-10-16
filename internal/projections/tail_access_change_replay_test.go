// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A live command projects its decision before the durable JetStream consumer
// acknowledges that event. After a restart, the consumer must replay the event
// without stopping at the already-terminal request, then reach later events.
func TestTailWorkerReplaysAlreadyProjectedAccessDecision(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	proj := projections.New(s)
	const requestID = "a579807b-8e50-4ad2-a1d0-5a82cdfa9b94"
	appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "tail-access-replay"})
	created := appendJSONEvent(t, log, projections.EventAccessChangeRequestCreated, tenantA, projections.AccessChangeRequestCreated{
		ID: requestID, RequestedAction: "revoke", RequesterSubject: "eval-admin",
		NHIID: "spiffe://qa.local/tail-access-replay", NHIKind: "spiffe", DisplayName: "QA reader",
		Resource: "local QA service", Entitlement: "read", ChangeRef: "jira:QA-TAIL-REPLAY",
		Reason: "durable cursor recovery", RequiredApprovals: 1,
	})

	// Establish a durable consumer that has acknowledged the request but has
	// not yet seen the decision. The command side then projects the decision
	// inline while its log event remains unread by that consumer.
	firstCtx, stopFirst := context.WithCancel(ctx)
	first := projections.NewTailWorker(log, proj, nil, time.Second)
	firstDone := make(chan error, 1)
	go func() { firstDone <- first.Run(firstCtx) }()
	waitFor(t, func() bool { return first.Applied() >= created.Sequence }, 20*time.Second, "tail request creation")
	stopFirst()
	select {
	case <-firstDone:
	case <-time.After(5 * time.Second):
		t.Fatal("first tail did not stop")
	}

	decision := appendJSONEvent(t, log, projections.EventAccessChangeRequestDecided, tenantA, projections.AccessChangeRequestDecided{
		RequestID: requestID, Decision: "approved", ApproverSubject: "eval-custodian-1",
	})
	if err := proj.Apply(ctx, decision); err != nil {
		t.Fatalf("inline decision projection: %v", err)
	}
	if err := proj.Apply(ctx, decision); !errors.Is(err, store.ErrAccessChangeRequestTerminal) {
		t.Fatalf("live command duplicate = %v, want terminal refusal", err)
	}
	later := appendJSONEvent(t, log, projections.EventOwnerCreated, tenantA,
		projections.OwnerCreated{ID: "00000000-0000-0000-0000-00000000a579", Kind: "Service", Name: "after-decision"})

	secondCtx, stopSecond := context.WithCancel(ctx)
	defer stopSecond()
	second := projections.NewTailWorker(log, proj, nil, time.Second)
	secondDone := make(chan error, 1)
	go func() { secondDone <- second.Run(secondCtx) }()
	deadline := time.After(20 * time.Second)
	for second.Applied() < later.Sequence {
		select {
		case err := <-secondDone:
			t.Fatalf("tail stopped before later event at seq %d: %v", later.Sequence, err)
		case <-deadline:
			t.Fatalf("tail stayed behind already-projected decision at seq %d; applied=%d", decision.Sequence, second.Applied())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if got := ownerCount(t, s, tenantA); got != 1 {
		t.Fatalf("later out-of-band owner count = %d, want 1", got)
	}
	request, err := s.GetAccessChangeRequest(ctx, tenantA, requestID)
	if err != nil || request.Status != "approved" || len(request.Decisions) != 1 {
		t.Fatalf("replayed request = %+v, %v", request, err)
	}
	stopSecond()
	select {
	case <-secondDone:
	case <-time.After(5 * time.Second):
		t.Fatal("second tail did not stop")
	}

	// Replay tolerance is limited to the first actor's already-recorded event.
	// A different actor's decision after terminal status is still a poison event.
	bad := appendJSONEvent(t, log, projections.EventAccessChangeRequestDecided, tenantA, projections.AccessChangeRequestDecided{
		RequestID: requestID, Decision: "denied", ApproverSubject: "eval-custodian-2",
	})
	thirdCtx, stopThird := context.WithTimeout(ctx, 5*time.Second)
	defer stopThird()
	third := projections.NewTailWorker(log, proj, nil, time.Second)
	if err := third.Run(thirdCtx); !errors.Is(err, store.ErrAccessChangeRequestTerminal) {
		t.Fatalf("new actor after terminal at seq %d = %v, want terminal refusal", bad.Sequence, err)
	}
	if request, err = s.GetAccessChangeRequest(ctx, tenantA, requestID); err != nil ||
		request.Status != "approved" || len(request.Decisions) != 1 {
		t.Fatalf("poison event changed first writer: %+v, %v", request, err)
	}
}
