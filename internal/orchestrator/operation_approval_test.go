// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/custody"
	ephemerallib "trstctl.com/trstctl/internal/ephemeral"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestEnsureOperationApprovalRequestSerializesCompetingIntentsAndRebuilds(t *testing.T) {
	s := newStore(t)
	resetOrchestratorOperationApprovals(t, s)
	ctx := context.Background()
	log := openLog(t)
	projector := projections.New(s)
	tenantEvent, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegisteredJSON("concurrent-operation-approvals"),
	})
	if err != nil {
		t.Fatalf("append tenant: %v", err)
	}
	if err := projector.Apply(ctx, tenantEvent); err != nil {
		t.Fatalf("project tenant: %v", err)
	}
	orch := orchestrator.NewOrchestrator(log, s, nil)

	// All commands target one approval scope, but each carries different immutable
	// command evidence and therefore has a different request ID/digest. Releasing
	// them together exercises the cross-replica shape: reads must not all observe an
	// empty scope and then publish multiple live authorities.
	const competitors = 24
	start := make(chan struct{})
	type result struct {
		request store.OperationApprovalRequest
		err     error
	}
	results := make(chan result, competitors)
	for i := 0; i < competitors; i++ {
		go func(index int) {
			<-start
			request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
				ResourceKind: "secret", ResourceID: "secret:concurrent/key",
				ResourceName: "concurrent/key", Action: "rotate", Requester: "alice",
				FromState: "version:1", ToState: fmt.Sprintf("version:%d", index+2),
				TargetVersion: 1, Reason: fmt.Sprintf("competing command %02d", index),
				EvidenceRefs:      []string{fmt.Sprintf("command-sha256:%064x", index+1)},
				RequiredApprovals: 2, TTL: time.Hour,
			})
			results <- result{request: request, err: err}
		}(i)
	}
	close(start)

	returned := make(map[string]struct{}, competitors)
	for i := 0; i < competitors; i++ {
		out := <-results
		if out.err != nil {
			t.Fatalf("concurrent ensure %d: %v", i, out.err)
		}
		if out.request.ID == "" || out.request.IntentDigest == "" {
			t.Fatalf("concurrent ensure %d returned incomplete authority: %+v", i, out.request)
		}
		returned[out.request.ID] = struct{}{}
	}
	if len(returned) != competitors {
		t.Fatalf("distinct competing intents returned %d request IDs, want %d", len(returned), competitors)
	}

	assertOneLive := func(stage string) {
		t.Helper()
		rows, err := s.ListOperationApprovals(ctx, tenantA, "", competitors+5)
		if err != nil {
			t.Fatalf("%s list approvals: %v", stage, err)
		}
		live := 0
		for _, row := range rows {
			if row.Status == store.ApprovalStatusPending || row.Status == store.ApprovalStatusApproved {
				live++
			}
		}
		if len(rows) != competitors || live != 1 {
			t.Fatalf("%s approval projection has %d rows/%d live, want %d rows/1 live: %+v",
				stage, len(rows), live, competitors, rows)
		}
	}
	assertOneLive("warm")

	requestEvents := 0
	seenEvents := make(map[string]struct{}, competitors)
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type != projections.EventApprovalRequested {
			return nil
		}
		var payload projections.ApprovalRequested
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return fmt.Errorf("decode request event %s: %w", event.ID, err)
		}
		if payload.ID != event.ID || payload.IntentDigest == "" {
			return fmt.Errorf("request event %s has incomplete canonical payload %+v", event.ID, payload)
		}
		if _, duplicate := seenEvents[event.ID]; duplicate {
			return fmt.Errorf("duplicate request event %s", event.ID)
		}
		seenEvents[event.ID] = struct{}{}
		requestEvents++
		return nil
	}); err != nil {
		t.Fatalf("inspect concurrent approval history: %v", err)
	}
	if requestEvents != competitors {
		t.Fatalf("approval.requested events = %d, want %d", requestEvents, competitors)
	}

	// Rebuild replays the exact append order into empty tables. A request event
	// published before its predecessor's supersession would either recreate two
	// live grants or poison a stricter projection; both are regressions.
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild concurrent approval history: %v", err)
	}
	assertOneLive("rebuilt")
}

func resetOrchestratorOperationApprovals(t *testing.T, s *store.Store) {
	t.Helper()
	reset := func() {
		t.Helper()
		if _, err := s.SystemPool().Exec(context.Background(),
			"TRUNCATE approved_target_event_fences, operation_approval_decisions, operation_approval_requests"); err != nil {
			t.Fatalf("truncate operation approvals: %v", err)
		}
	}
	reset()
	t.Cleanup(reset)
}

func TestOperationApprovalOrchestratorCanonicalRequestDecisionReplayAndQuorum(t *testing.T) {
	s := newStore(t)
	resetOrchestratorOperationApprovals(t, s)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "operation-approval"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, s, nil)

	intent := orchestrator.OperationApprovalIntent{
		ResourceKind: " code_signing ", ResourceID: " code-signing/payment-api ", ResourceName: " Payment API ",
		Action: " rotate ", Requester: " alice ", FromState: " active ", ToState: " rotated ",
		TargetVersion: 12, Reason: " scheduled rotation ",
		EvidenceRefs:      []string{" evidence:z ", "evidence:a", "evidence:z"},
		RequiredApprovals: 2, TTL: time.Hour,
	}
	request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, intent)
	if err != nil {
		t.Fatalf("ensure canonical request: %v", err)
	}
	if request.ID == "" || request.IntentDigest == "" || request.Requester != "alice" ||
		request.ResourceKind != "code_signing" || request.ResourceID != "code-signing/payment-api" {
		t.Fatalf("canonical request = %+v", request)
	}
	if len(request.EvidenceRefs) != 2 || request.EvidenceRefs[0] != "evidence:a" ||
		request.EvidenceRefs[1] != "evidence:z" {
		t.Fatalf("canonical evidence = %v, want sorted unique refs", request.EvidenceRefs)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}

	replayIntent := intent
	replayIntent.ResourceKind = "code_signing"
	replayIntent.ResourceID = "code-signing/payment-api"
	replayIntent.ResourceName = "Payment API"
	replayIntent.Action = "rotate"
	replayIntent.Requester = "alice"
	replayIntent.FromState = "active"
	replayIntent.ToState = "rotated"
	replayIntent.Reason = "scheduled rotation"
	replayIntent.EvidenceRefs = []string{"evidence:z", "evidence:a"}
	replay, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, replayIntent)
	if err != nil {
		t.Fatalf("ensure canonical replay: %v", err)
	}
	if replay.ID != request.ID || replay.IntentDigest != request.IntentDigest {
		t.Fatalf("canonical replay changed authority: first=%s/%s replay=%s/%s",
			request.ID, request.IntentDigest, replay.ID, replay.IntentDigest)
	}
	replayHead, err := log.LastSequence(ctx)
	if err != nil || replayHead != head {
		t.Fatalf("canonical replay appended another event: head %d -> %d, err=%v", head, replayHead, err)
	}

	if _, err := orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
		RequestID: request.ID, IntentDigest: request.IntentDigest,
		Approver: request.Requester, Decision: store.ApprovalDecisionApprove,
	}); !errors.Is(err, store.ErrApprovalSelfDecision) {
		t.Fatalf("self decision = %v, want ErrApprovalSelfDecision", err)
	}
	if _, err := orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
		RequestID: request.ID, IntentDigest: "sha256:wrong",
		Approver: "bob", Decision: store.ApprovalDecisionApprove,
	}); !errors.Is(err, store.ErrApprovalDigestMismatch) {
		t.Fatalf("wrong digest decision = %v, want ErrApprovalDigestMismatch", err)
	}

	firstDecision := orchestrator.OperationApprovalDecision{
		RequestID: request.ID, IntentDigest: request.IntentDigest,
		Approver: "bob", Decision: store.ApprovalDecisionApprove,
		ExpectedResourceKind: request.ResourceKind, ExpectedResourceID: request.ResourceID,
		ExpectedAction: request.Action,
	}
	afterFirst, err := orch.RecordOperationApprovalDecision(ctx, tenantA, firstDecision)
	if err != nil || afterFirst.ApprovalCount != 1 || afterFirst.Status != store.ApprovalStatusPending {
		t.Fatalf("first decision = (%+v, %v), want pending 1-of-2", afterFirst, err)
	}
	replayedDecision, replayErr := orch.RecordOperationApprovalDecision(ctx, tenantA, firstDecision)
	if replayErr != nil {
		t.Errorf("exact command replay = %v, want idempotent success", replayErr)
	} else if replayedDecision.ApprovalCount != 1 {
		t.Errorf("exact command replay count = %d, want 1", replayedDecision.ApprovalCount)
	}

	approved, err := orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
		RequestID: request.ID, IntentDigest: request.IntentDigest,
		Approver: "carol", Decision: store.ApprovalDecisionApprove,
		ExpectedResourceKind: request.ResourceKind, ExpectedResourceID: request.ResourceID,
		ExpectedAction: request.Action,
	})
	if err != nil || approved.Status != store.ApprovalStatusApproved || approved.ApprovalCount != 2 {
		t.Fatalf("second distinct decision = (%+v, %v), want approved 2-of-2", approved, err)
	}
}

func TestOperationApprovalDecisionConflictCannotPoisonLogOrColdRebuild(t *testing.T) {
	s := newStore(t)
	resetOrchestratorOperationApprovals(t, s)
	ctx := context.Background()
	log := openLog(t)
	projector := projections.New(s)
	tenantEvent, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegisteredJSON("approval-decision-conflict"),
	})
	if err != nil {
		t.Fatalf("append tenant: %v", err)
	}
	if err := projector.Apply(ctx, tenantEvent); err != nil {
		t.Fatalf("project tenant: %v", err)
	}
	orch := orchestrator.NewOrchestrator(log, s, nil)
	request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
		ResourceKind: "code_signing", ResourceID: "code-signing:decision-conflict", ResourceName: "decision-conflict",
		Action: "rotate", Requester: "alice", FromState: "version:1", ToState: "version:2",
		TargetVersion: 1, Reason: "one immutable command", EvidenceRefs: []string{"evidence:decision-conflict"},
		RequiredApprovals: 2, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("ensure request: %v", err)
	}
	first := orchestrator.OperationApprovalDecision{
		RequestID: request.ID, IntentDigest: request.IntentDigest,
		Approver: "bob", Decision: store.ApprovalDecisionApprove, Reason: "reviewed original evidence",
	}
	if _, err := orch.RecordOperationApprovalDecision(ctx, tenantA, first); err != nil {
		t.Fatalf("record first decision: %v", err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatalf("read head after first decision: %v", err)
	}

	changedReason := first
	changedReason.Reason = "different review reason"
	if _, err := orch.RecordOperationApprovalDecision(ctx, tenantA, changedReason); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Errorf("same principal changed reason = %v, want ErrIdempotencyConflict", err)
	}
	opposite := first
	opposite.Decision = store.ApprovalDecisionDeny
	if _, err := orch.RecordOperationApprovalDecision(ctx, tenantA, opposite); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Errorf("same principal opposite decision = %v, want ErrIdempotencyConflict", err)
	}
	if after, err := log.LastSequence(ctx); err != nil || after != head {
		t.Fatalf("conflicting decisions advanced log head = (%d, %v), want %d", after, err, head)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("cold rebuild after refused decision conflicts: %v", err)
	}
	rebuilt, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || rebuilt.Status != store.ApprovalStatusPending || rebuilt.ApprovalCount != 1 {
		t.Fatalf("rebuilt request = (%+v, %v), want pending with one immutable decision", rebuilt, err)
	}
}

func TestConcurrentOppositeApprovalDecisionsAppendOneRebuildableFact(t *testing.T) {
	s := newStore(t)
	resetOrchestratorOperationApprovals(t, s)
	ctx := context.Background()
	log := openLog(t)
	projector := projections.New(s)
	tenantEvent, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegisteredJSON("concurrent-opposite-approval-decisions"),
	})
	if err != nil {
		t.Fatalf("append tenant: %v", err)
	}
	if err := projector.Apply(ctx, tenantEvent); err != nil {
		t.Fatalf("project tenant: %v", err)
	}
	orch := orchestrator.NewOrchestrator(log, s, nil)
	request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
		ResourceKind: "code_signing", ResourceID: "code-signing:concurrent-decision", ResourceName: "concurrent-decision",
		Action: "rotate", Requester: "alice", FromState: "version:1", ToState: "version:2",
		TargetVersion: 1, Reason: "race opposite decisions", EvidenceRefs: []string{"evidence:opposite-race"},
		RequiredApprovals: 2, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("ensure request: %v", err)
	}
	headBefore, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, decision := range []string{store.ApprovalDecisionApprove, store.ApprovalDecisionDeny} {
		go func(decision string) {
			<-start
			_, err := orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
				RequestID: request.ID, IntentDigest: request.IntentDigest,
				Approver: "bob", Decision: decision, Reason: "one principal, one immutable vote",
			})
			results <- err
		}(decision)
	}
	close(start)
	succeeded, conflicted := 0, 0
	for range 2 {
		switch err := <-results; {
		case err == nil:
			succeeded++
		case errors.Is(err, store.ErrIdempotencyConflict):
			conflicted++
		default:
			t.Fatalf("concurrent opposite decision = %v, want success or ErrIdempotencyConflict", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent outcomes success=%d conflict=%d, want 1/1", succeeded, conflicted)
	}
	if headAfter, err := log.LastSequence(ctx); err != nil || headAfter != headBefore+1 {
		t.Fatalf("concurrent opposite decisions advanced head = (%d, %v), want %d", headAfter, err, headBefore+1)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("cold rebuild after concurrent opposite decisions: %v", err)
	}
	rebuilt, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || rebuilt.ApprovalCount > 1 ||
		(rebuilt.Status != store.ApprovalStatusPending && rebuilt.Status != store.ApprovalStatusDenied) {
		t.Fatalf("rebuilt concurrent decision = (%+v, %v), want exactly one approve or deny fact", rebuilt, err)
	}
}

func TestApprovalDecisionHoldsRequestLockBeforeAppendAcrossSupersession(t *testing.T) {
	s := newStore(t)
	resetOrchestratorOperationApprovals(t, s)
	ctx := context.Background()
	log := openLog(t)
	projector := projections.New(s)
	tenantEvent, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegisteredJSON("decision-supersession-lock"),
	})
	if err != nil {
		t.Fatalf("append tenant: %v", err)
	}
	if err := projector.Apply(ctx, tenantEvent); err != nil {
		t.Fatalf("project tenant: %v", err)
	}
	orch := orchestrator.NewOrchestrator(log, s, nil)
	request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
		ResourceKind: "secret", ResourceID: "secret:supersession-lock", ResourceName: "supersession-lock",
		Action: "rotate", Requester: "alice", FromState: "version:1", ToState: "version:2",
		TargetVersion: 1, Reason: "lock before append", EvidenceRefs: []string{"evidence:supersession-lock"},
		RequiredApprovals: 2, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("ensure request: %v", err)
	}
	headBefore, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}

	locked := make(chan struct{})
	supersede := make(chan struct{})
	blockerDone := make(chan error, 1)
	go func() {
		blockerDone <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if _, err := s.GetOperationApprovalForUpdateTx(ctx, tx, tenantA, request.ID); err != nil {
				return err
			}
			close(locked)
			<-supersede
			changedAt := time.Now().UTC()
			raw, err := json.Marshal(projections.ApprovalStatusChanged{
				RequestID: request.ID, IntentDigest: request.IntentDigest,
				Status: store.ApprovalStatusSuperseded, ChangedAt: changedAt,
			})
			if err != nil {
				return err
			}
			event, err := log.Append(ctx, events.Event{
				ID: events.NewID(), Type: projections.EventApprovalStatusChanged,
				TenantID: tenantA, Time: changedAt, Data: raw,
			})
			if err != nil {
				return err
			}
			return projector.ApplyTx(ctx, tx, event)
		})
	}()
	<-locked

	decisionDone := make(chan error, 1)
	go func() {
		_, err := orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
			RequestID: request.ID, IntentDigest: request.IntentDigest,
			Approver: "bob", Decision: store.ApprovalDecisionApprove,
		})
		decisionDone <- err
	}()
	// The decision command may read the row before this test's transaction, but it
	// must not append until it owns that row lock. The former implementation appended
	// immediately and only blocked when projection tried to acquire the lock.
	time.Sleep(150 * time.Millisecond)
	if head, err := log.LastSequence(ctx); err != nil || head != headBefore {
		t.Fatalf("decision appended before acquiring request lock = head %d err=%v, want %d", head, err, headBefore)
	}
	close(supersede)
	if err := <-blockerDone; err != nil {
		t.Fatalf("commit supersession: %v", err)
	}
	if err := <-decisionDone; !errors.Is(err, store.ErrApprovalSuperseded) {
		t.Fatalf("decision after locked supersession = %v, want ErrApprovalSuperseded", err)
	}
	if head, err := log.LastSequence(ctx); err != nil || head != headBefore+1 {
		t.Fatalf("supersession race head = (%d, %v), want only status event at %d", head, err, headBefore+1)
	}
	assertNoDecisions := func(stage string) {
		t.Helper()
		var count int
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM operation_approval_decisions
				WHERE tenant_id = $1 AND request_id = $2`, tenantA, request.ID).Scan(&count)
		}); err != nil || count != 0 {
			t.Fatalf("%s decisions = (%d, %v), want zero", stage, count, err)
		}
	}
	assertNoDecisions("warm")
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("cold rebuild after supersession race: %v", err)
	}
	assertNoDecisions("rebuilt")
	rebuilt, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || rebuilt.Status != store.ApprovalStatusSuperseded {
		t.Fatalf("rebuilt superseded request = (%+v, %v)", rebuilt, err)
	}
}

func TestOperationApprovalOrchestratorExpiryAndIdentityVersionDriftSupersede(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		s := newStore(t)
		resetOrchestratorOperationApprovals(t, s)
		ctx := context.Background()
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "expiry"}); err != nil {
			t.Fatal(err)
		}
		orch := orchestrator.NewOrchestrator(openLog(t), s, nil)
		request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
			ResourceKind: "secret", ResourceID: "secret/expired", Action: "rotate",
			Requester: "alice", TargetVersion: 1, RequiredApprovals: 1,
			TTL: 10 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("ensure expiring request: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
		if _, err := orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
			RequestID: request.ID, IntentDigest: request.IntentDigest,
			Approver: "bob", Decision: store.ApprovalDecisionApprove,
		}); !errors.Is(err, store.ErrApprovalExpired) {
			t.Fatalf("expired decision = %v, want ErrApprovalExpired", err)
		}
		got, err := s.GetOperationApproval(ctx, tenantA, request.ID)
		if err != nil || got.Status != store.ApprovalStatusExpired {
			t.Fatalf("expired request state = (%+v, %v)", got, err)
		}
	})

	t.Run("version-drift", func(t *testing.T) {
		s := newStore(t)
		resetOrchestratorOperationApprovals(t, s)
		ctx := context.Background()
		const identityID = "77200000-0000-4000-8000-000000000001"
		seedLifecycleIdentity(t, s, tenantA, identityID, orchestrator.StateRequested)
		orch := orchestrator.NewOrchestrator(openLog(t), s, nil)

		intent := orchestrator.OperationApprovalIntent{
			ResourceKind: "identity", ResourceID: identityID, ResourceName: "checkout",
			Action: "issue", Requester: "alice", FromState: string(orchestrator.StateRequested),
			ToState: string(orchestrator.StateIssued), TargetVersion: 0,
			Reason: "initial intent", RequiredApprovals: 1, TTL: time.Hour,
		}
		original, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, intent)
		if err != nil {
			t.Fatalf("ensure original request: %v", err)
		}
		intent.TargetVersion = 1
		intent.Reason = "changed target revision"
		replacement, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, intent)
		if err != nil {
			t.Fatalf("ensure replacement request: %v", err)
		}
		if replacement.ID == original.ID || replacement.IntentDigest == original.IntentDigest {
			t.Fatalf("target revision change reused authority: old=%s/%s new=%s/%s",
				original.ID, original.IntentDigest, replacement.ID, replacement.IntentDigest)
		}
		old, err := s.GetOperationApproval(ctx, tenantA, original.ID)
		if err != nil || old.Status != store.ApprovalStatusSuperseded {
			t.Fatalf("original after replacement = (%+v, %v), want superseded", old, err)
		}

		if _, err := orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
			RequestID: replacement.ID, IntentDigest: replacement.IntentDigest,
			Approver: "bob", Decision: store.ApprovalDecisionApprove,
		}); !errors.Is(err, store.ErrApprovalDrifted) {
			t.Fatalf("decision against drifted target = %v, want ErrApprovalDrifted", err)
		}
		drifted, err := s.GetOperationApproval(ctx, tenantA, replacement.ID)
		if err != nil || drifted.Status != store.ApprovalStatusSuperseded {
			t.Fatalf("drifted replacement state = (%+v, %v), want superseded", drifted, err)
		}
	})
}

func TestOperationApprovalDecisionRejectsDriftedCrossDomainTargets(t *testing.T) {
	assertRejectedWithoutDecision := func(t *testing.T, s *store.Store, log *events.Log, request store.OperationApprovalRequest, approver string) {
		t.Helper()
		decisionID := projections.OperationApprovalDecisionEventID(tenantA, request.ID, request.IntentDigest, approver)
		if _, err := orchestrator.NewOrchestrator(log, s, nil).RecordOperationApprovalDecision(
			context.Background(), tenantA, orchestrator.OperationApprovalDecision{
				RequestID: request.ID, IntentDigest: request.IntentDigest,
				Approver: approver, Decision: store.ApprovalDecisionApprove,
			}); !errors.Is(err, store.ErrApprovalDrifted) {
			t.Fatalf("decision against drifted %s target = %v, want ErrApprovalDrifted", request.ResourceKind, err)
		}
		got, err := s.GetOperationApproval(context.Background(), tenantA, request.ID)
		if err != nil || got.Status != store.ApprovalStatusSuperseded || got.ApprovalCount != 0 {
			t.Fatalf("drifted %s request = (%+v, %v), want superseded with zero approvals", request.ResourceKind, got, err)
		}
		var decisions int
		if err := s.SystemPool().QueryRow(context.Background(), `
			SELECT count(*) FROM operation_approval_decisions
			 WHERE tenant_id = $1 AND request_id = $2`, tenantA, request.ID).Scan(&decisions); err != nil {
			t.Fatalf("count drifted %s decisions: %v", request.ResourceKind, err)
		}
		if decisions != 0 {
			t.Fatalf("drifted %s decision rows = %d, want zero", request.ResourceKind, decisions)
		}
		if _, found, err := log.EventByID(context.Background(), decisionID); err != nil || found {
			t.Fatalf("drifted %s decision event = found %v err %v, want absent", request.ResourceKind, found, err)
		}
	}

	t.Run("application secret", func(t *testing.T) {
		s := newStore(t)
		resetOrchestratorOperationApprovals(t, s)
		ctx := context.Background()
		const name = "aud77/decision-drift-secret"
		if _, err := s.SystemPool().Exec(ctx, `
			INSERT INTO secret_store (tenant_id, name, sealed, version)
			VALUES ($1, $2, $3, 1)`, tenantA, name, []byte("sealed-v1")); err != nil {
			t.Fatalf("seed application-secret target: %v", err)
		}
		t.Cleanup(func() {
			_, _ = s.SystemPool().Exec(context.Background(),
				`DELETE FROM secret_store WHERE tenant_id = $1 AND name = $2`, tenantA, name)
		})
		log := openLog(t)
		orch := orchestrator.NewOrchestrator(log, s, nil)
		request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
			ResourceKind: "secret", ResourceID: "secret:" + name, ResourceName: name,
			Action: "rotate", Requester: "alice", FromState: "version:1",
			ToState: "version:2:command-hmac-sha256:aud77", TargetVersion: 1,
			Reason: "rotate exact secret generation", EvidenceRefs: []string{"current-version:1"},
			RequiredApprovals: 1, TTL: time.Hour,
		})
		if err != nil {
			t.Fatalf("ensure application-secret approval: %v", err)
		}
		if _, err := s.SystemPool().Exec(ctx,
			`UPDATE secret_store SET version = 2 WHERE tenant_id = $1 AND name = $2`, tenantA, name); err != nil {
			t.Fatalf("drift application-secret target: %v", err)
		}
		assertRejectedWithoutDecision(t, s, log, request, "bob")
	})

	t.Run("managed key", func(t *testing.T) {
		s := newStore(t)
		resetOrchestratorOperationApprovals(t, s)
		mustRegisterTenant(t, s, tenantA)
		ctx := context.Background()
		const provider = "aws-kms"
		const keyID = "aud77/decision-drift-key"
		if _, err := s.SystemPool().Exec(ctx, `
			INSERT INTO managed_keys
			       (tenant_id, provider, key_id, algorithm, version, state, public_der, created_at, updated_at)
			VALUES ($1, $2, $3, 'ECDSA-P256', 4, 'active', $4, now(), now())`,
			tenantA, provider, keyID, []byte("public-key")); err != nil {
			t.Fatalf("seed managed-key target: %v", err)
		}
		t.Cleanup(func() {
			_, _ = s.SystemPool().Exec(context.Background(), `
				DELETE FROM managed_keys WHERE tenant_id = $1 AND provider = $2 AND key_id = $3`,
				tenantA, provider, keyID)
		})
		log := openLog(t)
		orch := orchestrator.NewOrchestrator(log, s, nil)
		request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
			ResourceKind: "managed_key", ResourceID: keyID, ResourceName: keyID,
			Action: "managedkey:revoke", Requester: "alice", FromState: "active",
			ToState: "revoked", TargetVersion: 4,
			Reason:            "revoke exact managed-key generation",
			EvidenceRefs:      []string{"managed-key-provider:" + provider},
			RequiredApprovals: 1, TTL: time.Hour,
		})
		if err != nil {
			t.Fatalf("ensure managed-key approval: %v", err)
		}
		if _, err := s.SystemPool().Exec(ctx, `
			UPDATE managed_keys SET version = 5
			 WHERE tenant_id = $1 AND provider = $2 AND key_id = $3`, tenantA, provider, keyID); err != nil {
			t.Fatalf("drift managed-key target: %v", err)
		}
		assertRejectedWithoutDecision(t, s, log, request, "bob")
	})
}

func TestOperationApprovalOrchestratorLifecycleUseConsumesAndRebuildsOnce(t *testing.T) {
	s := newStore(t)
	resetOrchestratorOperationApprovals(t, s)
	ctx := context.Background()
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))

	owner, err := orch.CreateOwner(ctx, tenantA, "service", "approval-owner", "")
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	identity, err := orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "approval.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}
	const lifecycleKey = "approval-lifecycle-once"
	const lifecycleReason = "issue approved identity"
	request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
		ResourceKind: "identity", ResourceID: identity.ID, ResourceName: identity.Name,
		Action: "issue", Requester: "alice", FromState: string(orchestrator.StateRequested),
		ToState: string(orchestrator.StateIssued), TargetVersion: 0,
		Reason: lifecycleReason,
		EvidenceRefs: []string{
			"idempotency-key-sha256:" + crypto.SHA256Hex([]byte(lifecycleKey)),
		},
		RequiredApprovals: 1, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("ensure lifecycle approval: %v", err)
	}
	request, err = orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
		RequestID: request.ID, IntentDigest: request.IntentDigest,
		Approver: "bob", Decision: store.ApprovalDecisionApprove,
	})
	if err != nil || request.Status != store.ApprovalStatusApproved {
		t.Fatalf("approve lifecycle request = (%+v, %v)", request, err)
	}
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		t.Fatalf("build lifecycle approval use: %v", err)
	}
	if err := orch.TransitionWithSubjectCSRAndApproval(ctx, tenantA, identity.ID,
		orchestrator.StateIssued, lifecycleReason, lifecycleKey, "", use); err != nil {
		t.Fatalf("approved lifecycle transition: %v", err)
	}
	if err := orch.TransitionWithSubjectCSRAndApproval(ctx, tenantA, identity.ID,
		orchestrator.StateIssued, lifecycleReason, lifecycleKey, "", use); err != nil {
		t.Fatalf("exact approved lifecycle retry after commit: %v", err)
	}
	consumed, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || consumed.Status != store.ApprovalStatusConsumed || consumed.ConsumedEventID == "" {
		t.Fatalf("consumed lifecycle authority = (%+v, %v)", consumed, err)
	}
	issued, err := s.GetIdentity(ctx, tenantA, identity.ID)
	if err != nil || issued.Status != string(orchestrator.StateIssued) {
		t.Fatalf("issued identity = (%+v, %v)", issued, err)
	}

	if err := projections.New(s).Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild approved lifecycle: %v", err)
	}
	rebuilt, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || rebuilt.Status != store.ApprovalStatusConsumed ||
		rebuilt.ConsumedEventID != consumed.ConsumedEventID {
		t.Fatalf("rebuilt consumed authority = (%+v, %v), want event %s", rebuilt, err, consumed.ConsumedEventID)
	}
	rebuiltIdentity, err := s.GetIdentity(ctx, tenantA, identity.ID)
	if err != nil || rebuiltIdentity.Status != string(orchestrator.StateIssued) {
		t.Fatalf("rebuilt identity = (%+v, %v), want issued", rebuiltIdentity, err)
	}
}

func TestApprovedIdentityIssuanceRejectsProfileUpdateBeforeLifecycleAppend(t *testing.T) {
	s := newStore(t)
	resetOrchestratorOperationApprovals(t, s)
	ctx := context.Background()
	log := openLog(t)
	outbox := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, outbox)

	profileName := "approval-pin-stale"
	v1Spec := mustProfileSpec(t, profile.CertificateProfile{
		Name: profileName, RequiresApproval: true,
		AllowedEKUs: []string{"serverAuth"}, MaxValidity: profile.Duration(365 * 24 * time.Hour),
		AllowedProtocols: []string{"api"},
	})
	if _, err := s.CreateProfileVersion(ctx, store.ProfileRecord{
		TenantID: tenantA, Name: profileName, Spec: v1Spec, CreatedBy: "alice",
	}); err != nil {
		t.Fatalf("create profile v1: %v", err)
	}
	owner, err := orch.CreateOwner(ctx, tenantA, "service", "approval-pin-owner", "")
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	identity, err := orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "approval-pin.example.test", OwnerID: owner.ID,
		Attributes: json.RawMessage(`{"profile_name":"approval-pin-stale"}`),
	})
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}
	requirement, err := orch.ProfileApprovalRequirement(ctx, tenantA, identity.ID)
	if err != nil {
		t.Fatalf("resolve approved profile: %v", err)
	}
	evidence, err := requirement.IssuanceBinding().EvidenceRefs()
	if err != nil {
		t.Fatalf("issuance evidence: %v", err)
	}
	evidence = append(evidence,
		"idempotency-key-sha256:"+crypto.SHA256Hex([]byte("approval-pin-stale")))
	request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
		ResourceKind: "identity", ResourceID: identity.ID, ResourceName: identity.Name,
		Action: "issue", Requester: "alice", FromState: string(orchestrator.StateRequested),
		ToState: string(orchestrator.StateIssued), TargetVersion: 0,
		Reason: "authorize the exact profile revision", EvidenceRefs: evidence,
		RequiredApprovals: 1, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("ensure approval: %v", err)
	}
	request, err = orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
		RequestID: request.ID, IntentDigest: request.IntentDigest,
		Approver: "bob", Decision: store.ApprovalDecisionApprove,
	})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		t.Fatalf("build approved use: %v", err)
	}

	// Authorization already returned the v1 capability. A same-name v2 now
	// becomes active before the lifecycle transaction starts.
	v2Spec := mustProfileSpec(t, profile.CertificateProfile{
		Name: profileName, RequiresApproval: true,
		AllowedEKUs: []string{"clientAuth"}, MaxValidity: profile.Duration(time.Hour),
		AllowedProtocols: []string{"acme"},
	})
	if _, err := s.CreateProfileVersion(ctx, store.ProfileRecord{
		TenantID: tenantA, Name: profileName, Spec: v2Spec, CreatedBy: "carol",
	}); err != nil {
		t.Fatalf("create profile v2: %v", err)
	}
	headBefore, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pendingBefore, err := outbox.Pending(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}

	err = orch.TransitionWithSubjectCSRAndApproval(ctx, tenantA, identity.ID,
		orchestrator.StateIssued, "authorize the exact profile revision", "approval-pin-stale", "", use)
	if !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("stale approved profile transition = %v, want ErrApprovalDrifted", err)
	}
	if headAfter, headErr := log.LastSequence(ctx); headErr != nil || headAfter != headBefore+1 {
		t.Fatalf("stale authority event head = (%d, %v), want one supersession after %d", headAfter, headErr, headBefore)
	}
	pendingAfter, err := outbox.Pending(ctx, tenantA)
	if err != nil || len(pendingAfter) != len(pendingBefore) {
		t.Fatalf("stale authority outbox = (%d, %v), want unchanged %d", len(pendingAfter), err, len(pendingBefore))
	}
	got, err := s.GetIdentity(ctx, tenantA, identity.ID)
	if err != nil || got.Status != string(orchestrator.StateRequested) {
		t.Fatalf("identity after stale authority = (%+v, %v), want requested", got, err)
	}
	stale, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || stale.Status != store.ApprovalStatusSuperseded {
		t.Fatalf("stale authority status = (%+v, %v), want superseded", stale, err)
	}
}

func TestApprovedCertificateConsumesAuthorityAndRebuildsExactlyOnce(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "canonical"
		if legacy {
			name = "legacy-punctuation"
		}
		t.Run(name, func(t *testing.T) { testApprovedCertificateConsumesAuthorityAndRebuildsExactlyOnce(t, legacy) })
	}
}

func testApprovedCertificateConsumesAuthorityAndRebuildsExactlyOnce(t *testing.T, legacy bool) {
	const approvalTestCAID = "70146825-e5d7-48f6-ab79-168365686a09"
	s := newStore(t)
	resetOrchestratorOperationApprovals(t, s)
	ctx := context.Background()
	log := openLog(t)
	projector := projections.New(s)
	tenantEvent, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegisteredJSON("approved-certificate"),
	})
	if err != nil {
		t.Fatalf("append tenant: %v", err)
	}
	if err := projector.Apply(ctx, tenantEvent); err != nil {
		t.Fatalf("project tenant: %v", err)
	}
	orch := orchestrator.NewOrchestrator(log, s, nil)
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate approval test CA key: %v", err)
	}
	defer caKey.Destroy()
	caDER, err := crypto.SelfSignedCACert(caKey, "approved-certificate-test-ca", time.Hour)
	if err != nil {
		t.Fatalf("generate approval test CA: %v", err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate approved leaf key: %v", err)
	}
	defer leafKey.Destroy()
	spiffeID, approvedSubject := "spiffe://served.test/workload-7", "workload-7"
	if legacy {
		spiffeID, approvedSubject = "spiffe://served.test/repo:org/project%3Fref=main", "repo:org/project?ref=main"
	}
	const certificateTTL = 3 * time.Second
	binding, err := ephemerallib.NewApprovalBinding(approvalTestCAID, caDER, "workload-7", "test", approvedSubject,
		[]string{"selector:test"}, leafKey.Public().DER, spiffeID, certificateTTL)
	if err != nil {
		t.Fatalf("build certificate approval binding: %v", err)
	}
	toState, err := binding.ToState()
	if err != nil {
		t.Fatalf("build certificate approval state: %v", err)
	}
	evidenceRefs, err := binding.EvidenceRefs()
	if err != nil {
		t.Fatalf("build certificate approval evidence: %v", err)
	}
	request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
		ResourceKind: "ephemeral", ResourceID: "ephemeral:workload-7",
		ResourceName: "workload-7", Action: "issue", Requester: "alice",
		FromState: "attested", ToState: toState, RequiredApprovals: 1,
		Reason: "one exact ephemeral credential", EvidenceRefs: evidenceRefs,
		TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("ensure certificate approval: %v", err)
	}
	request, err = orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
		RequestID: request.ID, IntentDigest: request.IntentDigest,
		Approver: "bob", Decision: store.ApprovalDecisionApprove,
		ExpectedResourceKind: "ephemeral", ExpectedResourceID: "ephemeral:workload-7",
		ExpectedAction: "issue",
	})
	if err != nil {
		t.Fatalf("approve certificate request: %v", err)
	}
	use := store.OperationApprovalUse{
		RequestID: request.ID, IntentDigest: request.IntentDigest,
		Requester: request.Requester, ResourceKind: request.ResourceKind,
		ResourceID: request.ResourceID, Action: request.Action,
		FromState: request.FromState, ToState: request.ToState,
		TargetVersion: request.TargetVersion, RequiredApprovals: request.RequiredApprovals,
	}
	// Mint after the immutable approval exists, exactly like the served issuance
	// path. Minting first makes the certificate's lifetime start before the
	// authority window, so the production validator correctly refuses it.
	certificateDER, err := signApprovedCertificateFixture(caDER, caKey, leafKey, spiffeID, certificateTTL, legacy)
	if err != nil {
		t.Fatalf("sign approved certificate after approval: %v", err)
	}
	certificateInfo, err := certinfo.Inspect(certificateDER)
	if err != nil {
		t.Fatalf("inspect approved certificate: %v", err)
	}
	nb, na := certificateInfo.NotBefore, certificateInfo.NotAfter
	certificate := store.Certificate{
		CAID: approvalTestCAID, Subject: certificateInfo.Subject, SANs: []string{spiffeID}, Issuer: certificateInfo.Issuer,
		Serial: certificateInfo.SerialNumber, Fingerprint: certificateInfo.SHA256Fingerprint,
		KeyAlgorithm: certificateInfo.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
		Source: "ephemeral:test", CertificateDER: certificateDER,
		IssuanceIdempotencyKey: "ephemeral-issue:" + request.ID,
		KeyOrigin:              "requester",
	}
	tamperedMetadata := certificate
	tamperedMetadata.SANs = []string{"spiffe://served.test/different-workload"}
	if _, err := orch.RecordCertificateWithApproval(ctx, tenantA, tamperedMetadata, use, binding); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("record approved certificate with swapped SAN metadata = %v, want ErrApprovalDrifted", err)
	}
	stillApproved, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || stillApproved.Status != store.ApprovalStatusApproved {
		t.Fatalf("metadata swap changed approval = (%+v, %v), want approved", stillApproved, err)
	}
	certificateEvents := 0
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type == projections.EventCertificateRecorded {
			certificateEvents++
		}
		return nil
	}); err != nil || certificateEvents != 0 {
		t.Fatalf("metadata swap retained certificate events = %d, replay err %v; want 0", certificateEvents, err)
	}
	// The rejected metadata control above deliberately performs database and
	// event-log work before the real issuance. Refresh the still-identical
	// approved certificate here so a heavily loaded race run tests the canonical
	// record path, not whether that unrelated negative control consumed most of a
	// three-second fixture lifetime. The binding, key, SPIFFE ID, CA, and TTL are
	// unchanged; only the signer-owned serial and issuance clock advance.
	certificateDER, err = signApprovedCertificateFixture(caDER, caKey, leafKey, spiffeID, certificateTTL, legacy)
	if err != nil {
		t.Fatalf("refresh approved certificate after metadata control: %v", err)
	}
	certificateInfo, err = certinfo.Inspect(certificateDER)
	if err != nil {
		t.Fatalf("inspect refreshed approved certificate: %v", err)
	}
	nb, na = certificateInfo.NotBefore, certificateInfo.NotAfter
	certificate = store.Certificate{
		CAID: approvalTestCAID, Subject: certificateInfo.Subject, SANs: []string{spiffeID}, Issuer: certificateInfo.Issuer,
		Serial: certificateInfo.SerialNumber, Fingerprint: certificateInfo.SHA256Fingerprint,
		KeyAlgorithm: certificateInfo.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
		Source: "ephemeral:test", CertificateDER: certificateDER,
		IssuanceIdempotencyKey: "ephemeral-issue:" + request.ID,
		KeyOrigin:              "requester",
	}
	first, err := orch.RecordCertificateWithApproval(ctx, tenantA, certificate, use, binding)
	if err != nil {
		t.Fatalf("record approved certificate: %v", err)
	}
	replay, err := orch.RecordCertificateWithApproval(ctx, tenantA, certificate, use, binding)
	if err != nil {
		t.Fatalf("replay approved certificate: %v", err)
	}
	if replay.ID != first.ID || replay.Fingerprint != first.Fingerprint {
		t.Fatalf("approved certificate replay changed result: first=%+v replay=%+v", first, replay)
	}
	consumed, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil {
		t.Fatalf("load consumed certificate approval: %v", err)
	}
	wantEventID := orchestrator.CertificateApprovalEventID(tenantA, use)
	if consumed.Status != store.ApprovalStatusConsumed || consumed.ConsumedEventID != wantEventID {
		t.Fatalf("consumed certificate approval = %+v, want event %s", consumed, wantEventID)
	}

	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild approved certificate: %v", err)
	}
	rebuiltRequest, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || rebuiltRequest.Status != store.ApprovalStatusConsumed || rebuiltRequest.ConsumedEventID != wantEventID {
		t.Fatalf("rebuilt approval = (%+v, %v), want consumed by %s", rebuiltRequest, err, wantEventID)
	}
	rebuiltCertificate, err := s.GetCertificateByFingerprint(ctx, tenantA, certificate.Fingerprint)
	if err != nil || rebuiltCertificate.ID != first.ID || !bytes.Equal(rebuiltCertificate.CertificateDER, certificateDER) ||
		len(rebuiltCertificate.SANs) != 1 || rebuiltCertificate.SANs[0] != spiffeID {
		t.Fatalf("rebuilt certificate = (%+v, %v), want id %s", rebuiltCertificate, err, first.ID)
	}
	if wait := time.Until(na.Add(100 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	expiredReplay, err := orch.RecordCertificateWithApproval(ctx, tenantA, certificate, use, binding)
	if err != nil || expiredReplay.ID != first.ID || expiredReplay.Fingerprint != first.Fingerprint {
		t.Fatalf("post-expiry exact replay = (%+v, %v), want canonical certificate %+v", expiredReplay, err, first)
	}

	otherLeafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate mismatched approved leaf key: %v", err)
	}
	defer otherLeafKey.Destroy()
	const otherSPIFFEID = "spiffe://served.test/workload-8"
	otherBinding, err := ephemerallib.NewApprovalBinding(approvalTestCAID, caDER, "workload-8", "test", "workload-8",
		[]string{"selector:other"}, otherLeafKey.Public().DER, otherSPIFFEID, certificateTTL)
	if err != nil {
		t.Fatalf("build mismatched certificate binding: %v", err)
	}
	otherToState, _ := otherBinding.ToState()
	otherEvidence, _ := otherBinding.EvidenceRefs()
	otherRequest, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
		ResourceKind: "ephemeral", ResourceID: "ephemeral:workload-8", ResourceName: "workload-8",
		Action: "issue", Requester: "carol", FromState: "attested", ToState: otherToState,
		Reason: "one other exact ephemeral credential", EvidenceRefs: otherEvidence,
		RequiredApprovals: 1, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("ensure mismatched certificate approval: %v", err)
	}
	otherRequest, err = orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
		RequestID: otherRequest.ID, IntentDigest: otherRequest.IntentDigest,
		Approver: "dave", Decision: store.ApprovalDecisionApprove,
		ExpectedResourceKind: "ephemeral", ExpectedResourceID: "ephemeral:workload-8", ExpectedAction: "issue",
	})
	if err != nil {
		t.Fatalf("approve mismatched certificate request: %v", err)
	}
	otherUse := store.OperationApprovalUse{
		RequestID: otherRequest.ID, IntentDigest: otherRequest.IntentDigest, Requester: otherRequest.Requester,
		ResourceKind: otherRequest.ResourceKind, ResourceID: otherRequest.ResourceID, Action: otherRequest.Action,
		FromState: otherRequest.FromState, ToState: otherRequest.ToState,
		TargetVersion: otherRequest.TargetVersion, RequiredApprovals: otherRequest.RequiredApprovals,
	}
	poisonedEventID := projections.CertificateApprovalEventID(tenantA, otherUse)
	poisonedPayload := projections.CertificateRecorded{
		ID: projections.CertificateApprovalRowID(tenantA, otherUse), CAID: approvalTestCAID,
		Subject: certificateInfo.Subject, SANs: []string{spiffeID}, Issuer: certificateInfo.Issuer,
		Serial: certificateInfo.SerialNumber, Fingerprint: certificateInfo.SHA256Fingerprint,
		KeyAlgorithm: certificateInfo.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
		Source: "ephemeral:test", CertificateDER: certificateDER,
		IssuanceIdempotencyKey: "ephemeral-issue:" + otherRequest.ID,
		KeyOrigin:              string(custody.OriginRequester), Approval: &otherUse, ApprovalBinding: &otherBinding,
	}
	poisonedRaw, err := json.Marshal(poisonedPayload)
	if err != nil {
		t.Fatalf("marshal poisoned certificate event: %v", err)
	}
	if _, err := log.Append(ctx, events.Event{
		ID: poisonedEventID, Type: projections.EventCertificateRecorded, TenantID: tenantA,
		Time: time.Now().UTC(), SchemaVersion: projections.CertificateApprovalEventSchemaVersion, Data: poisonedRaw,
	}); err != nil {
		t.Fatalf("append retained mismatched certificate event: %v", err)
	}
	if err := projector.Rebuild(ctx, log); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("cold rebuild with approval A/certificate B = %v, want ErrApprovalDrifted", err)
	}
	otherAfter, err := s.GetOperationApproval(ctx, tenantA, otherRequest.ID)
	if err != nil || otherAfter.Status != store.ApprovalStatusApproved || otherAfter.ConsumedEventID != "" {
		t.Fatalf("rejected retained certificate changed authority = (%+v, %v), want approved", otherAfter, err)
	}
	var poisonedRows int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM certificates WHERE tenant_id = $1 AND id = $2`,
		tenantA, projections.CertificateApprovalRowID(tenantA, otherUse)).Scan(&poisonedRows); err != nil || poisonedRows != 0 {
		t.Fatalf("rejected retained certificate rows = %d, query err %v; want 0", poisonedRows, err)
	}
}

func TestApprovedCertificateColdRebuildSurvivesRewrittenApprovalEvidence(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "canonical"
		if legacy {
			name = "legacy-punctuation"
		}
		t.Run(name, func(t *testing.T) { testApprovedCertificateColdRebuildSurvivesRewrittenApprovalEvidence(t, legacy) })
	}
}

func testApprovedCertificateColdRebuildSurvivesRewrittenApprovalEvidence(t *testing.T, legacy bool) {
	const approvalTestCAID = "38d24371-1101-4c86-b4de-0b974bee24b5"
	s := newStore(t)
	resetOrchestratorOperationApprovals(t, s)
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithHistoryRewriteContinuityVerifier(func(context.Context, events.TenantDataContinuityEvidence) error { return nil }))
	if err != nil {
		t.Fatalf("open rewrite-ready event log: %v", err)
	}
	defer func() { _ = log.Close() }()
	projector := projections.New(s)
	tenantEvent, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegisteredJSON("rewritten-approved-certificate"),
	})
	if err != nil {
		t.Fatalf("append tenant: %v", err)
	}
	if err := projector.Apply(ctx, tenantEvent); err != nil {
		t.Fatalf("project tenant: %v", err)
	}
	orch := orchestrator.NewOrchestrator(log, s, nil)

	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate rewrite test CA key: %v", err)
	}
	defer caKey.Destroy()
	caDER, err := crypto.SelfSignedCACert(caKey, "rewritten-approved-certificate-ca", time.Hour)
	if err != nil {
		t.Fatalf("generate rewrite test CA: %v", err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate rewrite test leaf key: %v", err)
	}
	defer leafKey.Destroy()
	spiffeID, approvedSubject := "spiffe://served.test/retained-workload", "retained-workload"
	if legacy {
		spiffeID, approvedSubject = "spiffe://served.test/repo:org/project%3Fref=main", "repo:org/project?ref=main"
	}
	// This fixture proves retained-event recovery, not near-expiry behavior. A
	// ten-minute lifetime keeps the certificate valid while the race+coverage
	// suite deliberately contends on the shared PostgreSQL test instance; the
	// separate ephemeral approval tests retain the exact lifetime boundaries.
	const certificateTTL = 10 * time.Minute
	binding, err := ephemerallib.NewApprovalBinding(approvalTestCAID, caDER, "retained-workload", "test",
		approvedSubject, []string{"selector:retained"}, leafKey.Public().DER, spiffeID, certificateTTL)
	if err != nil {
		t.Fatalf("build rewrite test binding: %v", err)
	}
	toState, _ := binding.ToState()
	evidence, _ := binding.EvidenceRefs()
	request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
		ResourceKind: "ephemeral", ResourceID: "ephemeral:retained-workload", ResourceName: "retained-workload",
		Action: "issue", Requester: "retained-requester", FromState: "attested", ToState: toState,
		Reason: "retained evidence rebuild", EvidenceRefs: evidence, RequiredApprovals: 1, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("ensure rewrite test approval: %v", err)
	}
	request, err = orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
		RequestID: request.ID, IntentDigest: request.IntentDigest, Approver: "retained-approver",
		Decision: store.ApprovalDecisionApprove, ExpectedResourceKind: "ephemeral",
		ExpectedResourceID: request.ResourceID, ExpectedAction: "issue",
	})
	if err != nil {
		t.Fatalf("approve rewrite test request: %v", err)
	}
	// Issue only after the immutable approval is ready, matching the served
	// workflow. Signing before approval made the later target-event clock
	// correctly reject a certificate minted outside the authority window and hid
	// the cold-rebuild assertions this fixture exists to prove.
	certificateDER, err := signApprovedCertificateFixture(caDER, caKey, leafKey, spiffeID, certificateTTL, legacy)
	if err != nil {
		t.Fatalf("sign rewrite test certificate after approval: %v", err)
	}
	info, err := certinfo.Inspect(certificateDER)
	if err != nil {
		t.Fatalf("inspect rewrite test certificate: %v", err)
	}
	use := store.OperationApprovalUse{
		RequestID: request.ID, IntentDigest: request.IntentDigest, Requester: request.Requester,
		ResourceKind: request.ResourceKind, ResourceID: request.ResourceID, Action: request.Action,
		FromState: request.FromState, ToState: request.ToState,
		TargetVersion: request.TargetVersion, RequiredApprovals: request.RequiredApprovals,
	}
	nb, na := info.NotBefore, info.NotAfter
	recorded, err := orch.RecordCertificateWithApproval(ctx, tenantA, store.Certificate{
		CAID: approvalTestCAID, Subject: info.Subject, SANs: []string{spiffeID}, Issuer: info.Issuer,
		Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm,
		NotBefore: &nb, NotAfter: &na, Source: "ephemeral:test", CertificateDER: certificateDER,
		IssuanceIdempotencyKey: "ephemeral-issue:" + request.ID, KeyOrigin: string(custody.OriginRequester),
	}, use, binding)
	if err != nil {
		t.Fatalf("record rewrite test certificate: %v", err)
	}

	changed, err := log.RewriteTenantData(ctx, tenantA,
		func(eventType string, _ int, data []byte) ([]byte, bool, error) {
			if eventType != projections.EventApprovalRequested {
				return data, false, nil
			}
			var payload projections.ApprovalRequested
			if err := json.Unmarshal(data, &payload); err != nil {
				return nil, false, err
			}
			if payload.ID != request.ID {
				return data, false, nil
			}
			payload.EvidenceRefs = []string{}
			rewritten, err := json.Marshal(payload)
			return rewritten, true, err
		},
		events.WithTenantDataPairValidator(func(eventType string, _ int, before, after []byte) error {
			if eventType != projections.EventApprovalRequested || string(before) == string(after) {
				return errors.New("approval evidence rewrite changed the wrong event")
			}
			var payload projections.ApprovalRequested
			if err := json.Unmarshal(after, &payload); err != nil {
				return err
			}
			if payload.ID != request.ID || len(payload.EvidenceRefs) != 0 || payload.IntentDigest != request.IntentDigest {
				return errors.New("approval evidence rewrite changed immutable authority")
			}
			return nil
		}),
		events.WithTenantDataCutoverPreparation(func(ctx context.Context, _ events.TenantDataRewriteReport, proceed func(context.Context) error) error {
			return proceed(ctx)
		}),
		events.WithTenantDataAuditContinuity(func(context.Context, events.TenantDataAuditView) (events.TenantDataAuditCheckpoint, error) {
			return events.TenantDataAuditCheckpoint{IdentityDigest: crypto.SHA256Hex([]byte("rewritten-evidence-test"))}, nil
		}),
		events.WithTenantDataContinuity(func(_ context.Context, report events.TenantDataRewriteReport) (events.Event, error) {
			data, err := json.Marshal(report)
			return events.Event{ID: "rewrite-receipt-" + report.OperationID, Type: "tenant.data.rewrite.receipt",
				TenantID: report.TenantID, Time: report.CompletedAt, Data: data}, err
		}),
	)
	if err != nil || changed != 1 {
		t.Fatalf("rewrite approval evidence = (%d, %v), want 1 changed", changed, err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("cold rebuild after approval evidence rewrite: %v", err)
	}
	rebuiltRequest, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || rebuiltRequest.Status != store.ApprovalStatusConsumed ||
		rebuiltRequest.ConsumedEventID != projections.CertificateApprovalEventID(tenantA, use) ||
		len(rebuiltRequest.EvidenceRefs) != 0 {
		t.Fatalf("rebuilt rewritten approval = (%+v, %v), want consumed with no evidence", rebuiltRequest, err)
	}
	rebuiltCertificate, err := s.GetCertificateByFingerprint(ctx, tenantA, info.SHA256Fingerprint)
	if err != nil || rebuiltCertificate.ID != recorded.ID || !bytes.Equal(rebuiltCertificate.CertificateDER, certificateDER) ||
		len(rebuiltCertificate.SANs) != 1 || rebuiltCertificate.SANs[0] != spiffeID {
		t.Fatalf("rebuilt rewritten certificate = (%+v, %v), want id %s", rebuiltCertificate, err, recorded.ID)
	}
}

func TestApprovedCertificateRevalidatesSupersessionAfterOutsideRecoveryLookup(t *testing.T) {
	const approvalTestCAID = "0c0ea3f1-1a77-44d4-ab9f-dd2150118476"
	s := newStore(t)
	resetOrchestratorOperationApprovals(t, s)
	ctx := context.Background()
	log := openLog(t)
	projector := projections.New(s)
	tenantEvent, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegisteredJSON("certificate-outside-lookup-race"),
	})
	if err != nil {
		t.Fatalf("append tenant: %v", err)
	}
	if err := projector.Apply(ctx, tenantEvent); err != nil {
		t.Fatalf("project tenant: %v", err)
	}
	orch := orchestrator.NewOrchestrator(log, s, nil)
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate race test CA key: %v", err)
	}
	defer caKey.Destroy()
	caDER, err := crypto.SelfSignedCACert(caKey, "certificate-outside-lookup-race", time.Hour)
	if err != nil {
		t.Fatalf("generate race test CA: %v", err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate race test leaf key: %v", err)
	}
	defer leafKey.Destroy()
	const spiffeID = "spiffe://served.test/outside-lookup-race"
	certificateDER, err := crypto.SignSVID(caDER, caKey, leafKey.Public().DER, spiffeID, 10*time.Second)
	if err != nil {
		t.Fatalf("sign race test certificate: %v", err)
	}
	info, err := certinfo.Inspect(certificateDER)
	if err != nil {
		t.Fatalf("inspect race test certificate: %v", err)
	}
	// Reviewers authorize a one-second maximum. The ten-second certificate makes
	// command preflight enter the retained-event recovery lookup without waiting
	// for wall-clock expiry.
	binding, err := ephemerallib.NewApprovalBinding(approvalTestCAID, caDER, "outside-lookup-race", "test",
		"outside-lookup-race", []string{"selector:race"}, leafKey.Public().DER, spiffeID, time.Second)
	if err != nil {
		t.Fatalf("build race test binding: %v", err)
	}
	toState, _ := binding.ToState()
	evidence, _ := binding.EvidenceRefs()
	request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
		ResourceKind: "ephemeral", ResourceID: "ephemeral:outside-lookup-race", ResourceName: "outside-lookup-race",
		Action: "issue", Requester: "race-requester", FromState: "attested", ToState: toState,
		Reason: "outside lookup must revalidate", EvidenceRefs: evidence, RequiredApprovals: 1, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("ensure race test approval: %v", err)
	}
	request, err = orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
		RequestID: request.ID, IntentDigest: request.IntentDigest, Approver: "race-approver",
		Decision: store.ApprovalDecisionApprove, ExpectedResourceKind: "ephemeral",
		ExpectedResourceID: request.ResourceID, ExpectedAction: "issue",
	})
	if err != nil {
		t.Fatalf("approve race test request: %v", err)
	}
	use := store.OperationApprovalUse{
		RequestID: request.ID, IntentDigest: request.IntentDigest, Requester: request.Requester,
		ResourceKind: request.ResourceKind, ResourceID: request.ResourceID, Action: request.Action,
		FromState: request.FromState, ToState: request.ToState,
		TargetVersion: request.TargetVersion, RequiredApprovals: request.RequiredApprovals,
	}
	nb, na := info.NotBefore, info.NotAfter
	certificate := store.Certificate{
		CAID: approvalTestCAID, Subject: info.Subject, SANs: []string{spiffeID}, Issuer: info.Issuer,
		Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm,
		NotBefore: &nb, NotAfter: &na, Source: "ephemeral:test", CertificateDER: certificateDER,
		IssuanceIdempotencyKey: "ephemeral-issue:" + request.ID, KeyOrigin: string(custody.OriginRequester),
	}

	locked := make(chan struct{})
	releaseSupersession := make(chan struct{})
	blockerDone := make(chan error, 1)
	go func() {
		blockerDone <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if _, err := s.GetOperationApprovalForUpdateTx(ctx, tx, tenantA, request.ID); err != nil {
				return err
			}
			close(locked)
			<-releaseSupersession
			changedAt := time.Now().UTC()
			raw, err := json.Marshal(projections.ApprovalStatusChanged{
				RequestID: request.ID, IntentDigest: request.IntentDigest,
				Status: store.ApprovalStatusSuperseded, ChangedAt: changedAt,
			})
			if err != nil {
				return err
			}
			event, err := log.Append(ctx, events.Event{
				ID: events.NewID(), Type: projections.EventApprovalStatusChanged,
				TenantID: tenantA, Time: changedAt, Data: raw,
			})
			if err != nil {
				return err
			}
			return projector.ApplyTx(ctx, tx, event)
		})
	}()
	<-locked
	recordDone := make(chan error, 1)
	go func() {
		_, err := orch.RecordCertificateWithApproval(ctx, tenantA, certificate, use, binding)
		recordDone <- err
	}()
	time.Sleep(150 * time.Millisecond)
	close(releaseSupersession)
	if err := <-blockerDone; err != nil {
		t.Fatalf("commit certificate approval supersession: %v", err)
	}
	if err := <-recordDone; !errors.Is(err, store.ErrApprovalSuperseded) {
		t.Fatalf("certificate command after outside lookup/supersession = %v, want ErrApprovalSuperseded", err)
	}
	after, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || after.Status != store.ApprovalStatusSuperseded || after.ConsumedEventID != "" {
		t.Fatalf("raced certificate approval = (%+v, %v), want unconsumed superseded", after, err)
	}
	var certificateEvents int
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type == projections.EventCertificateRecorded {
			certificateEvents++
		}
		return nil
	}); err != nil || certificateEvents != 0 {
		t.Fatalf("raced certificate target events = %d, replay err %v; want 0", certificateEvents, err)
	}
}

func TestCodeSigningColdRebuildKeepsConflictingApprovalUnconsumed(t *testing.T) {
	s := newStore(t)
	resetOrchestratorOperationApprovals(t, s)
	ctx := context.Background()
	const duplicateWindow = 100 * time.Millisecond
	log := openLogWithOptions(t, events.WithDuplicateWindowForTesting(duplicateWindow))
	projector := projections.New(s)
	tenantEvent, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegisteredJSON("code-signing-idempotency-collision"),
	})
	if err != nil {
		t.Fatalf("append tenant: %v", err)
	}
	if err := projector.Apply(ctx, tenantEvent); err != nil {
		t.Fatalf("project tenant: %v", err)
	}
	orch := orchestrator.NewOrchestrator(log, s, nil)
	const (
		idempotencyKey = "retained-code-signing-key"
		requestHashA   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		requestHashB   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	operationID := projections.LegacyCodeSigningOperationID(tenantA, idempotencyKey)
	eventID := projections.CodeSigningApprovalEventID(tenantA, operationID)
	ensureApproval := func(resourceName, requester, requestHash string) (store.OperationApprovalRequest, store.OperationApprovalUse) {
		t.Helper()
		request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
			ResourceKind: "code_signing", ResourceID: store.CodeSigningApprovalResourceID(requestHash, idempotencyKey),
			ResourceName: resourceName, Action: "sign", Requester: requester,
			Reason: "one exact code-signing command", EvidenceRefs: []string{"request-sha256:" + requestHash},
			RequiredApprovals: 1, TTL: time.Hour,
		})
		if err != nil {
			t.Fatalf("ensure %s approval: %v", resourceName, err)
		}
		request, err = orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
			RequestID: request.ID, IntentDigest: request.IntentDigest, Approver: "security-" + requester,
			Decision: store.ApprovalDecisionApprove, ExpectedResourceKind: "code_signing",
			ExpectedResourceID: request.ResourceID, ExpectedAction: "sign",
		})
		if err != nil {
			t.Fatalf("approve %s request: %v", resourceName, err)
		}
		use, err := store.OperationApprovalUseFromRequest(request)
		if err != nil {
			t.Fatalf("build %s approval use: %v", resourceName, err)
		}
		return request, use
	}
	requestA, useA := ensureApproval("release-a", "builder-a", requestHashA)
	payloadA, _ := json.Marshal(projections.CodeSigningCommanded{
		OperationID: operationID, IdempotencyKey: idempotencyKey,
		Mode: "key", RequestHash: requestHashA, SealedCommand: []byte("sealed-command-a"), Approval: &useA,
	})
	eventA, err := log.Append(ctx, events.Event{
		ID: eventID, Type: projections.EventCodeSigningCommanded, TenantID: tenantA,
		Time: time.Now().UTC(), SchemaVersion: projections.CodeSigningApprovalEventSchemaVersion, Data: payloadA,
	})
	if err != nil {
		t.Fatalf("append code-signing A: %v", err)
	}
	if err := projector.Apply(ctx, eventA); err != nil {
		t.Fatalf("project code-signing A: %v", err)
	}
	consumedA, err := s.GetOperationApproval(ctx, tenantA, requestA.ID)
	if err != nil || consumedA.Status != store.ApprovalStatusConsumed || consumedA.ConsumedEventID != eventID {
		t.Fatalf("code-signing A authority = (%+v, %v), want consumed", consumedA, err)
	}

	requestB, useB := ensureApproval("release-b", "builder-b", requestHashB)
	payloadB, _ := json.Marshal(projections.CodeSigningCommanded{
		OperationID: operationID, IdempotencyKey: idempotencyKey,
		Mode: "keyless", RequestHash: requestHashB, SealedCommand: []byte("sealed-command-b"), Approval: &useB,
	})
	// Cross JetStream's real finite Msg-Id memory. The second conflicting event
	// deliberately reuses the only legal deterministic event ID, proving cold
	// rebuild correctness does not come from the broker suppressing it forever.
	time.Sleep(4 * duplicateWindow)
	if _, err := log.Append(ctx, events.Event{
		ID: eventID, Type: projections.EventCodeSigningCommanded, TenantID: tenantA,
		Time: time.Now().UTC(), SchemaVersion: projections.CodeSigningApprovalEventSchemaVersion, Data: payloadB,
	}); err != nil {
		t.Fatalf("append retained code-signing B: %v", err)
	}
	if err := projector.Rebuild(ctx, log); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("cold rebuild same-key command collision = %v, want ErrIdempotencyConflict", err)
	}
	afterB, err := s.GetOperationApproval(ctx, tenantA, requestB.ID)
	if err != nil || afterB.Status != store.ApprovalStatusApproved || afterB.ConsumedEventID != "" {
		t.Fatalf("conflicting rebuild consumed B authority = (%+v, %v), want approved", afterB, err)
	}
	operationA, ok, err := s.CodeSigningOperationByID(ctx, tenantA, operationID)
	if err != nil || !ok || operationA.RequestHash != requestHashA {
		t.Fatalf("authoritative operation A after rejected rebuild = (%+v, %t, %v)", operationA, ok, err)
	}
}

// signApprovedCertificateFixture uses the ordinary nonreserved CSR boundary
// solely to model a pre-canonical historical certificate. Production automatic
// issuance must still reject the same legacy URI. No signer or parser is relaxed.
func signApprovedCertificateFixture(caDER []byte, caKey, leafKey crypto.DigestSigner, spiffeID string, ttl time.Duration, legacy bool) ([]byte, error) {
	if !legacy {
		return crypto.SignSVID(caDER, caKey, leafKey.Public().DER, spiffeID, ttl)
	}
	if _, err := crypto.SignSVID(caDER, caKey, leafKey.Public().DER, spiffeID, ttl); err == nil {
		return nil, errors.New("strict automatic issuance accepted a legacy URI")
	}
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{URIs: []string{spiffeID}}, leafKey)
	if err != nil {
		return nil, err
	}
	return crypto.SignLeafFromCSRWithProfile(caDER, caKey, csr, ttl, crypto.LeafProfile{})
}
