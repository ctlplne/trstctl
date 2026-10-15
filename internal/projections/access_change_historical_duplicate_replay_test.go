// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestAccessChangeHistoricalDuplicateDecisionKeepsFirstWriterThroughColdReplay(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	p := projections.New(s)
	const requestID = "6c861a56-5118-49b8-8a2b-0d3a1eea51cb"
	appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "access-history"})
	appendJSONEvent(t, log, projections.EventAccessChangeRequestCreated, tenantA, projections.AccessChangeRequestCreated{
		ID: requestID, RequestedAction: "revoke", RequesterSubject: "eval-admin",
		NHIID: "spiffe://qa.local/access-history", NHIKind: "spiffe", DisplayName: "QA reader",
		Resource: "local QA service", Entitlement: "read", ChangeRef: "jira:QA-ACCESS-HISTORY",
		Reason: "retained first-writer proof", RequiredApprovals: 2,
	})
	first := projections.AccessChangeRequestDecided{
		RequestID: requestID, Decision: "approved", ApproverSubject: "eval-custodian-1",
		Reason: "first accepted decision", DecisionEvidenceRefs: []string{"qa:first-writer"},
		DecidedAt: time.Date(2026, 10, 15, 8, 30, 0, 0, time.UTC),
	}
	appendJSONEvent(t, log, projections.EventAccessChangeRequestDecided, tenantA, first)
	appendJSONEvent(t, log, projections.EventAccessChangeRequestDecided, tenantA, projections.AccessChangeRequestDecided{
		RequestID: requestID, Decision: "denied", ApproverSubject: "eval-custodian-1",
		Reason: "later rejected event", DecisionEvidenceRefs: []string{"qa:later-conflict"},
		DecidedAt: first.DecidedAt.Add(time.Minute),
	})
	appendJSONEvent(t, log, projections.EventAccessChangeRequestDecided, tenantA, projections.AccessChangeRequestDecided{
		RequestID: requestID, Decision: "approved", ApproverSubject: "eval-custodian-2",
		DecisionEvidenceRefs: []string{"qa:distinct-second-writer"},
		DecidedAt:            first.DecidedAt.Add(2 * time.Minute),
	})

	check := func(stage string) {
		t.Helper()
		got, err := s.GetAccessChangeRequest(ctx, tenantA, requestID)
		if err != nil {
			t.Fatalf("%s read request: %v", stage, err)
		}
		if got.Status != "approved" || got.ApprovalCount != 2 || len(got.Decisions) != 2 {
			t.Fatalf("%s status=%s approvals=%d decisions=%d", stage, got.Status, got.ApprovalCount, len(got.Decisions))
		}
		for _, decision := range got.Decisions {
			if decision.ApproverSubject != "eval-custodian-1" {
				continue
			}
			if decision.Decision != "approved" || decision.Reason != first.Reason ||
				len(decision.DecisionEvidenceRefs) != 1 || decision.DecisionEvidenceRefs[0] != "qa:first-writer" {
				t.Fatalf("%s first writer changed: %+v", stage, decision)
			}
			return
		}
		t.Fatalf("%s first writer missing: %+v", stage, got.Decisions)
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("cold catch-up refused retained duplicate: %v", err)
	}
	check("catch-up")
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("full rebuild refused retained duplicate: %v", err)
	}
	check("full rebuild")

	// Command-side projection must still reject a new duplicate. Recovery only
	// accepts historical log replay; it cannot reopen approval authority.
	liveDuplicate := appendJSONEvent(t, log, projections.EventAccessChangeRequestDecided, tenantA, first)
	if err := p.Apply(ctx, liveDuplicate); !errors.Is(err, store.ErrAccessChangeRequestTerminal) &&
		!errors.Is(err, store.ErrAccessChangeDecisionDuplicate) {
		t.Fatalf("live duplicate was accepted: %v", err)
	}
	check("live refusal")

	count := 0
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type == projections.EventAccessChangeRequestDecided {
			count++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("append-only history lost a decision event: %d", count)
	}
}

func TestAccessChangeHistoricalReplayStillRejectsNewActorAfterTerminalDecision(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	p := projections.New(s)
	const requestID = "b9c3ed07-1077-4f4d-b215-58d774bf9a20"
	appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "access-terminal"})
	appendJSONEvent(t, log, projections.EventAccessChangeRequestCreated, tenantA, projections.AccessChangeRequestCreated{
		ID: requestID, RequestedAction: "revoke", RequesterSubject: "eval-admin",
		NHIID: "spiffe://qa.local/access-terminal", NHIKind: "spiffe", DisplayName: "QA reader",
		Resource: "local QA service", Entitlement: "read", ChangeRef: "jira:QA-ACCESS-TERMINAL",
		Reason: "terminal authority proof", RequiredApprovals: 1,
	})
	appendJSONEvent(t, log, projections.EventAccessChangeRequestDecided, tenantA, projections.AccessChangeRequestDecided{
		RequestID: requestID, Decision: "approved", ApproverSubject: "eval-custodian-1",
	})
	appendJSONEvent(t, log, projections.EventAccessChangeRequestDecided, tenantA, projections.AccessChangeRequestDecided{
		RequestID: requestID, Decision: "denied", ApproverSubject: "eval-custodian-2",
	})
	if err := p.ProjectCatchUp(ctx, log); !errors.Is(err, store.ErrAccessChangeRequestTerminal) {
		t.Fatalf("distinct actor was silently accepted after terminal decision: %v", err)
	}
}
