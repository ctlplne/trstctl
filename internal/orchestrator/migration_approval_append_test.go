// SPDX-License-Identifier: BUSL-1.1
package orchestrator_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestMigrationApprovalRefusesSecondStartBeforeAppendC0337(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
		ResourceKind: "migration_run", ResourceID: "plan-c0337", ResourceName: "plan-c0337",
		Action: "start", Requester: "alice", EvidenceRefs: []string{"migration-intent:fixture"},
		RequiredApprovals: 1, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
		RequestID: request.ID, IntentDigest: request.IntentDigest, Approver: "bob", Decision: store.ApprovalDecisionApprove,
	}); err != nil {
		t.Fatal(err)
	}
	request, err = st.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || request.Status != store.ApprovalStatusApproved {
		t.Fatalf("approval not ready: %+v err=%v", request, err)
	}
	approval := &migration.ApprovalUse{
		RequestID: request.ID, IntentDigest: request.IntentDigest, Requester: request.Requester,
		ResourceKind: request.ResourceKind, ResourceID: request.ResourceID, Action: request.Action,
		FromState: request.FromState, ToState: request.ToState, TargetVersion: request.TargetVersion,
		RequiredApprovals: request.RequiredApprovals, Reason: request.Reason, EvidenceRefs: request.EvidenceRefs,
	}
	makeRun := func(id string) (migration.Run, []migration.Action) {
		t.Helper()
		run, actions, err := migration.StartRun(migration.Run{ID: id, Approval: approval,
			Waves: []migration.RunWave{{ID: "canary", Ordinal: 1, Members: []migration.RunMember{{
				IdentityID: "identity-a", Binding: migration.MemberBinding{
					IssuingAuthorityID: "40400000-0000-4000-8000-000000000043",
					TargetID:           "target-a", TargetRevision: "revision-a", Connector: "nginx", Target: "edge-a",
					TargetConfig:    json.RawMessage(`{"executor":"agent","required_agent_id":"40400000-0000-4000-8000-000000000041"}`),
					RequiredAgentID: "40400000-0000-4000-8000-000000000041",
					TrustAnchorPath: "/etc/trstctl/next-root.pem", TrustAnchorPEM: []byte("public-ca-pem"),
					TrustAnchorFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					VerifyAddress:          "127.0.0.1:443", SubjectCommonName: "edge.example.test",
					SubjectDNSNames:          []string{"edge.example.test"},
					PredecessorCertificateID: "40400000-0000-4000-8000-000000000042",
					PredecessorFingerprint:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				},
			}}}}})
		if err != nil {
			t.Fatal(err)
		}
		return run, actions
	}
	firstID := "40400000-0000-4000-8000-000000000061"
	secondID := "40400000-0000-4000-8000-000000000062"
	first, firstActions := makeRun(firstID)
	firstEvent := orchestrator.MigrationEventID(tenantA, firstID, "start")
	if _, err := orch.RecordMigrationRun(ctx, tenantA, firstEvent, first, firstActions); err != nil {
		t.Fatalf("first authorized start: %v", err)
	}
	second, secondActions := makeRun(secondID)
	secondEvent := orchestrator.MigrationEventID(tenantA, secondID, "start")
	if _, err := orch.RecordMigrationRun(ctx, tenantA, secondEvent, second, secondActions); !errors.Is(err, store.ErrApprovalConsumed) {
		t.Fatalf("second start error=%v, want consumed approval", err)
	}
	if _, found, err := log.EventByID(ctx, secondEvent); err != nil || found {
		t.Fatalf("unprojectable second start reached JetStream: found=%v err=%v", found, err)
	}
	if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("losing start poisoned shared catch-up: %v", err)
	}
	if _, err := orch.RecordMigrationRun(ctx, tenantA, firstEvent, first, firstActions); err != nil {
		t.Fatalf("exact retry of consumed start failed: %v", err)
	}
	// Two fresh starts with the same approved intent race under distinct
	// idempotency keys. The database approval lock must serialize them before
	// either can append an event, and exactly one run may win.
	raceRequest, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
		ResourceKind: "migration_run", ResourceID: "plan-c0337-race", ResourceName: "plan-c0337-race",
		Action: "start", Requester: "alice", EvidenceRefs: []string{"migration-intent:race"},
		RequiredApprovals: 1, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
		RequestID: raceRequest.ID, IntentDigest: raceRequest.IntentDigest,
		Approver: "bob", Decision: store.ApprovalDecisionApprove,
	}); err != nil {
		t.Fatal(err)
	}
	raceRequest, err = st.GetOperationApproval(ctx, tenantA, raceRequest.ID)
	if err != nil {
		t.Fatal(err)
	}
	approval = &migration.ApprovalUse{
		RequestID: raceRequest.ID, IntentDigest: raceRequest.IntentDigest, Requester: raceRequest.Requester,
		ResourceKind: raceRequest.ResourceKind, ResourceID: raceRequest.ResourceID, Action: raceRequest.Action,
		FromState: raceRequest.FromState, ToState: raceRequest.ToState, TargetVersion: raceRequest.TargetVersion,
		RequiredApprovals: raceRequest.RequiredApprovals, Reason: raceRequest.Reason, EvidenceRefs: raceRequest.EvidenceRefs,
	}
	type startResult struct {
		id  string
		err error
	}
	results := make(chan startResult, 2)
	var wg sync.WaitGroup
	for _, id := range []string{"40400000-0000-4000-8000-000000000063", "40400000-0000-4000-8000-000000000064"} {
		run, actions := makeRun(id)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := orch.RecordMigrationRun(ctx, tenantA, orchestrator.MigrationEventID(tenantA, id, "start"), run, actions)
			results <- startResult{id: id, err: err}
		}()
	}
	wg.Wait()
	close(results)
	winners, losers := 0, 0
	for result := range results {
		switch {
		case result.err == nil:
			winners++
		case errors.Is(result.err, store.ErrApprovalConsumed):
			losers++
			if _, found, err := log.EventByID(ctx, orchestrator.MigrationEventID(tenantA, result.id, "start")); err != nil || found {
				t.Fatalf("racing loser reached JetStream: found=%v err=%v", found, err)
			}
		default:
			t.Fatalf("racing start failed unexpectedly: %v", result.err)
		}
	}
	if winners != 1 || losers != 1 {
		t.Fatalf("racing approval admitted %d winners and %d losers", winners, losers)
	}
	// Reopen the historical shape from an older binary that appended before
	// validating. It remains in the immutable log, but only this tenant must
	// enter incident quarantine; a later tenant must keep projecting.
	oldBody, err := json.Marshal(projections.MigrationRunRecorded{Run: second, Actions: secondActions})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{ID: secondEvent, Type: projections.EventMigrationRunRecorded,
		TenantID: tenantA, Data: oldBody}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantB,
		Data: []byte(`{"name":"Healthy"}`)}); err != nil {
		t.Fatal(err)
	}
	p := projections.New(st)
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("historical losing start blocked global catch-up: %v", err)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || !quarantined {
		t.Fatalf("historical losing start quarantine=%v err=%v", quarantined, err)
	}
	if _, err := st.GetTenant(ctx, tenantB); err != nil {
		t.Fatalf("later healthy tenant was not projected: %v", err)
	}
	if _, err := orch.ReconcileOutbox(ctx, log); err != nil {
		t.Fatalf("outbox reconciliation stopped on rejected historical start: %v", err)
	}
	loserKey := "migration:" + secondID + ":canary:identity-a:distribute_trust"
	if n := countOutbox(t, ctx, st.SystemPool(), tenantA, loserKey); n != 0 {
		t.Fatalf("historical losing start queued %d external actions", n)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("historical losing start blocked rebuild: %v", err)
	}
}
