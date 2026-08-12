// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const approvalDurabilityDuplicateWindow = 100 * time.Millisecond

func TestOperationApprovalRequestRecoversRetainedPrivacyEventAfterFiniteDedupe(t *testing.T) {
	const (
		tenantID = "33333333-3333-3333-3333-333333333333"
		subject  = "approval-requester@example.test"
	)
	s := newStore(t)
	resetOrchestratorOperationApprovals(t, s)
	ctx := context.Background()
	requestCtx := events.ContextWithActor(ctx, events.Actor{
		Subject: subject, Roles: []string{"secret-writer"},
	})
	log := lifecycleRewriteLog(t, events.WithDuplicateWindowForTesting(approvalDurabilityDuplicateWindow))
	projector := projections.New(s)
	tenantEvent, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantID,
		Data: tenantRegisteredJSON("approval-durability-request"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, tenantEvent); err != nil {
		t.Fatal(err)
	}
	outbox := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, outbox)
	intent := orchestrator.OperationApprovalIntent{
		ResourceKind: "secret", ResourceID: "secret:durability/request", ResourceName: "durability/request",
		Action: "rotate", Requester: subject, FromState: "version:1", ToState: "version:2",
		Reason: "rotate for " + subject, EvidenceRefs: []string{"ticket:" + subject},
		RequiredApprovals: 1, TTL: 2 * time.Hour,
	}
	requestID := operationApprovalRequestIDForTest(t, tenantID, intent)
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO outbox
			(tenant_id, destination, effect_lane, payload, idempotency_key)
			VALUES ($1, 'notification.conflict', 'notification.conflict', 'conflict', $2)`,
			tenantID, "approval-request:"+requestID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// The request Append succeeds, then a pre-seeded receiver-key conflict makes
	// its projection+notification transaction roll back: the exact
	// receiver-commit/process-crash boundary.
	if _, err := orch.EnsureOperationApprovalRequest(requestCtx, tenantID, intent); err == nil {
		t.Fatal("approval request unexpectedly committed through outbox conflict")
	}
	if _, err := s.SystemPool().Exec(ctx,
		`DELETE FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantID, "approval-request:"+requestID); err != nil {
		t.Fatal(err)
	}
	requestEvent := oneApprovalEvent(t, log, tenantID, projections.EventApprovalRequested)
	var original projections.ApprovalRequested
	if err := json.Unmarshal(requestEvent.Data, &original); err != nil {
		t.Fatal(err)
	}
	if original.Requester != subject || original.ExpiresAt.Sub(original.CreatedAt) != intent.TTL {
		t.Fatalf("first retained request = %+v", original)
	}
	if requestEvent.Actor == nil || requestEvent.Actor.Subject != subject {
		t.Fatalf("first retained request actor = %+v, want %q", requestEvent.Actor, subject)
	}
	if _, err := s.GetOperationApproval(ctx, tenantID, original.ID); !errors.Is(err, store.ErrApprovalRequestNotFound) {
		t.Fatalf("rolled-back request projection = %v, want not found", err)
	}

	if err := log.PseudonymizeSubject(ctx, tenantID, subject, lifecycleRewriteProofOptions(nil)...); err != nil {
		t.Fatalf("privacy-shape retained request: %v", err)
	}
	time.Sleep(4 * approvalDurabilityDuplicateWindow)
	recovered, err := orch.EnsureOperationApprovalRequest(requestCtx, tenantID, intent)
	if err != nil {
		t.Fatalf("recover retained approval request: %v", err)
	}
	if recovered.ID != original.ID || recovered.IntentDigest != original.IntentDigest ||
		!recovered.CreatedAt.Equal(original.CreatedAt) || recovered.Requester == subject {
		t.Fatalf("recovered request did not preserve canonical authority/privacy: %+v", recovered)
	}
	retained, found, err := log.EventByID(ctx, original.ID)
	if err != nil || !found || bytes.Contains(retained.Data, []byte(subject)) {
		t.Fatalf("privacy-shaped retained request = (found=%t err=%v data=%s)", found, err, retained.Data)
	}
	if retained.Actor == nil || retained.Actor.Subject == subject ||
		!strings.HasPrefix(retained.Actor.Subject, "erased:") {
		t.Fatalf("privacy-shaped retained request actor = %+v", retained.Actor)
	}
	if countEventsByID(t, log, original.ID) != 1 {
		t.Fatalf("request %s was republished after finite dedupe expiry", original.ID)
	}

	var notification []byte
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT payload FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantID, "approval-request:"+original.ID).Scan(&notification); err != nil {
		t.Fatalf("load recovered approval notification: %v", err)
	}
	if bytes.Contains(notification, []byte(subject)) {
		t.Fatalf("recovered approval notification restored erased subject: %s", notification)
	}

	changedTTL := intent
	changedTTL.TTL = 3 * time.Hour // TTL is not in the request UUID; retained bytes must reject it.
	if _, err := orch.EnsureOperationApprovalRequest(requestCtx, tenantID, changedTTL); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed retained request TTL = %v, want ErrIdempotencyConflict", err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("cold rebuild recovered approval request: %v", err)
	}
	rebuilt, err := s.GetOperationApproval(ctx, tenantID, original.ID)
	if err != nil || rebuilt.IntentDigest != original.IntentDigest || rebuilt.Requester == subject {
		t.Fatalf("rebuilt privacy-shaped request = (%+v, %v)", rebuilt, err)
	}
}

func TestOperationApprovalDecisionRecoversRetainedPrivacyEventAfterFiniteDedupe(t *testing.T) {
	const subject = "approval-reviewer@example.test"
	s := newStore(t)
	resetOrchestratorOperationApprovals(t, s)
	ctx := context.Background()
	requestCtx := events.ContextWithActor(ctx, events.Actor{
		Subject: "requester@example.test", Roles: []string{"secret-writer"},
	})
	decisionCtx := events.ContextWithActor(ctx, events.Actor{
		Subject: subject, Roles: []string{"secret-approver"},
	})
	log := lifecycleRewriteLog(t, events.WithDuplicateWindowForTesting(approvalDurabilityDuplicateWindow))
	projector := projections.New(s)
	seedApprovalTenant(t, projector, log, tenantA, "approval-durability-decision")
	orch := orchestrator.NewOrchestrator(log, s, nil)
	request, err := orch.EnsureOperationApprovalRequest(requestCtx, tenantA, orchestrator.OperationApprovalIntent{
		ResourceKind: "secret", ResourceID: "secret:durability/decision", ResourceName: "durability/decision",
		Action: "rotate", Requester: "requester@example.test", FromState: "version:1", ToState: "version:2",
		Reason: "decision durability", EvidenceRefs: []string{"ticket:decision"},
		RequiredApprovals: 1, TTL: 2 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	decision := orchestrator.OperationApprovalDecision{
		RequestID: request.ID, IntentDigest: request.IntentDigest, Approver: subject,
		Decision: store.ApprovalDecisionApprove, Reason: "reviewed by " + subject,
		ExpectedResourceKind: request.ResourceKind, ExpectedResourceID: request.ResourceID,
		ExpectedAction: request.Action,
	}
	eventID := projections.OperationApprovalDecisionEventID(tenantA,
		decision.RequestID, decision.IntentDigest, decision.Approver)
	decidedAt := request.CreatedAt.Add(5 * time.Minute)
	raw, err := json.Marshal(projections.ApprovalDecisionRecorded{
		RequestID: decision.RequestID, IntentDigest: decision.IntentDigest,
		Approver: decision.Approver, Decision: decision.Decision, Reason: decision.Reason,
		DecidedAt: decidedAt, ExpectedResourceKind: decision.ExpectedResourceKind,
		ExpectedResourceID: decision.ExpectedResourceID, ExpectedAction: decision.ExpectedAction,
	})
	if err != nil {
		t.Fatal(err)
	}
	decisionEvent := events.Event{
		ID: eventID, Type: projections.EventApprovalDecisionRecorded,
		TenantID: tenantA, Time: decidedAt, Data: raw,
	}
	if _, err := log.Append(decisionCtx, decisionEvent); err != nil {
		t.Fatalf("append orphaned decision: %v", err)
	}
	if err := log.PseudonymizeSubject(ctx, tenantA, subject, lifecycleRewriteProofOptions(nil)...); err != nil {
		t.Fatalf("privacy-shape retained decision: %v", err)
	}
	time.Sleep(4 * approvalDurabilityDuplicateWindow)
	recovered, err := orch.RecordOperationApprovalDecision(decisionCtx, tenantA, decision)
	if err != nil {
		t.Fatalf("recover retained approval decision: %v", err)
	}
	if recovered.Status != store.ApprovalStatusApproved || recovered.ApprovalCount != 1 {
		t.Fatalf("recovered decision request = %+v", recovered)
	}
	var approver string
	var projectedAt time.Time
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT approver, decided_at FROM operation_approval_decisions
		  WHERE tenant_id = $1 AND request_id = $2`, tenantA, request.ID).Scan(&approver, &projectedAt); err != nil {
		t.Fatal(err)
	}
	if approver == subject || !projectedAt.Equal(decidedAt) {
		t.Fatalf("recovered decision approver/time = %q/%s, want erased/%s", approver, projectedAt, decidedAt)
	}
	if countEventsByID(t, log, eventID) != 1 {
		t.Fatalf("decision %s retained event count changed during recovery", eventID)
	}
	changed := decision
	changed.Reason = "different review"
	if _, err := orch.RecordOperationApprovalDecision(decisionCtx, tenantA, changed); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed retained decision = %v, want ErrIdempotencyConflict", err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("cold rebuild retained decision: %v", err)
	}
	rebuilt, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || rebuilt.Status != store.ApprovalStatusApproved || rebuilt.ApprovalCount != 1 {
		t.Fatalf("rebuilt retained decision = (%+v, %v)", rebuilt, err)
	}
}

func TestOperationApprovalDecisionAcceptsExactPhysicalDuplicateAfterFiniteDedupe(t *testing.T) {
	s := newStore(t)
	resetOrchestratorOperationApprovals(t, s)
	ctx := context.Background()
	log := openLogWithOptions(t, events.WithDuplicateWindowForTesting(approvalDurabilityDuplicateWindow))
	projector := projections.New(s)
	seedApprovalTenant(t, projector, log, tenantA, "approval-durability-exact-duplicate")
	orch := orchestrator.NewOrchestrator(log, s, nil)
	request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
		ResourceKind: "secret", ResourceID: "secret:durability/exact-duplicate", ResourceName: "exact-duplicate",
		Action: "rotate", Requester: "duplicate-requester", FromState: "version:1", ToState: "version:2",
		Reason: "exact duplicate", EvidenceRefs: []string{"ticket:exact-duplicate"},
		RequiredApprovals: 1, TTL: 2 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	decision := orchestrator.OperationApprovalDecision{
		RequestID: request.ID, IntentDigest: request.IntentDigest, Approver: "duplicate-reviewer",
		Decision: store.ApprovalDecisionApprove, Reason: "exact retained decision",
		ExpectedResourceKind: request.ResourceKind, ExpectedResourceID: request.ResourceID,
		ExpectedAction: request.Action,
	}
	eventID := projections.OperationApprovalDecisionEventID(tenantA,
		decision.RequestID, decision.IntentDigest, decision.Approver)
	decidedAt := request.CreatedAt.Add(5 * time.Minute)
	raw, err := json.Marshal(projections.ApprovalDecisionRecorded{
		RequestID: decision.RequestID, IntentDigest: decision.IntentDigest,
		Approver: decision.Approver, Decision: decision.Decision, Reason: decision.Reason,
		DecidedAt: decidedAt, ExpectedResourceKind: decision.ExpectedResourceKind,
		ExpectedResourceID: decision.ExpectedResourceID, ExpectedAction: decision.ExpectedAction,
	})
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{
		ID: eventID, Type: projections.EventApprovalDecisionRecorded,
		TenantID: tenantA, Time: decidedAt, Data: raw,
	}
	first, err := log.Append(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * approvalDurabilityDuplicateWindow)
	second, err := log.Append(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	if second.Sequence == first.Sequence {
		t.Fatalf("broker suppressed exact duplicate after finite window at sequence %d", first.Sequence)
	}
	recovered, err := orch.RecordOperationApprovalDecision(ctx, tenantA, decision)
	if err != nil || recovered.Status != store.ApprovalStatusApproved {
		t.Fatalf("recover exact duplicate decision = (%+v, %v)", recovered, err)
	}
	if countEventsByID(t, log, eventID) != 2 {
		t.Fatalf("exact decision duplicate history count changed")
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("cold rebuild exact duplicate decision: %v", err)
	}
}

func TestOperationApprovalStatusRecoversRetainedEventAfterFiniteDedupe(t *testing.T) {
	t.Run("exact and cold replay", func(t *testing.T) {
		s := newStore(t)
		resetOrchestratorOperationApprovals(t, s)
		ctx := context.Background()
		requestCtx := events.ContextWithActor(ctx, events.Actor{
			Subject: "status-requester", Roles: []string{"secret-writer"},
		})
		statusCtx := events.ContextWithActor(ctx, events.Actor{
			Subject: "status-reviewer", Roles: []string{"secret-approver"},
		})
		log := openLogWithOptions(t, events.WithDuplicateWindowForTesting(approvalDurabilityDuplicateWindow))
		projector := projections.New(s)
		seedApprovalTenant(t, projector, log, tenantA, "approval-durability-status")
		orch := orchestrator.NewOrchestrator(log, s, nil)
		oldIntent, replacementIntent := durabilityStatusIntents()
		old, err := orch.EnsureOperationApprovalRequest(requestCtx, tenantA, oldIntent)
		if err != nil {
			t.Fatal(err)
		}
		replacementID := operationApprovalRequestIDForTest(t, tenantA, replacementIntent)
		eventID := projections.OperationApprovalStatusEventID(tenantA, old.ID,
			old.IntentDigest, store.ApprovalStatusSuperseded, replacementID)
		changedAt := old.CreatedAt.Add(10 * time.Minute)
		raw, _ := json.Marshal(projections.ApprovalStatusChanged{
			RequestID: old.ID, IntentDigest: old.IntentDigest,
			Status: store.ApprovalStatusSuperseded, ChangedAt: changedAt, ReplacementID: replacementID,
		})
		if _, err := log.Append(statusCtx, events.Event{
			ID: eventID, Type: projections.EventApprovalStatusChanged,
			TenantID: tenantA, Time: changedAt, Data: raw,
		}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(4 * approvalDurabilityDuplicateWindow)
		replacement, err := orch.EnsureOperationApprovalRequest(requestCtx, tenantA, replacementIntent)
		if err != nil {
			t.Fatalf("recover retained supersession: %v", err)
		}
		if replacement.ID != replacementID {
			t.Fatalf("replacement id = %s, want %s", replacement.ID, replacementID)
		}
		after, err := s.GetOperationApproval(ctx, tenantA, old.ID)
		if err != nil || after.Status != store.ApprovalStatusSuperseded || !after.UpdatedAt.Equal(changedAt) {
			t.Fatalf("recovered status = (%+v, %v)", after, err)
		}
		if countEventsByID(t, log, eventID) != 1 {
			t.Fatalf("status %s was republished after finite dedupe expiry", eventID)
		}
		if err := projector.Rebuild(ctx, log); err != nil {
			t.Fatalf("cold rebuild retained status: %v", err)
		}
		rebuilt, err := s.GetOperationApproval(ctx, tenantA, old.ID)
		if err != nil || rebuilt.Status != store.ApprovalStatusSuperseded {
			t.Fatalf("rebuilt status = (%+v, %v)", rebuilt, err)
		}
	})

	t.Run("changed status payload rejected", func(t *testing.T) {
		s := newStore(t)
		resetOrchestratorOperationApprovals(t, s)
		ctx := context.Background()
		log := openLogWithOptions(t, events.WithDuplicateWindowForTesting(approvalDurabilityDuplicateWindow))
		projector := projections.New(s)
		seedApprovalTenant(t, projector, log, tenantA, "approval-durability-status-conflict")
		orch := orchestrator.NewOrchestrator(log, s, nil)
		oldIntent, replacementIntent := durabilityStatusIntents()
		old, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, oldIntent)
		if err != nil {
			t.Fatal(err)
		}
		replacementID := operationApprovalRequestIDForTest(t, tenantA, replacementIntent)
		eventID := projections.OperationApprovalStatusEventID(tenantA, old.ID,
			old.IntentDigest, store.ApprovalStatusSuperseded, replacementID)
		changedAt := old.CreatedAt.Add(10 * time.Minute)
		canonicalRaw, _ := json.Marshal(projections.ApprovalStatusChanged{
			RequestID: old.ID, IntentDigest: old.IntentDigest,
			Status: store.ApprovalStatusSuperseded, ChangedAt: changedAt, ReplacementID: replacementID,
		})
		if _, err := log.Append(ctx, events.Event{
			ID: eventID, Type: projections.EventApprovalStatusChanged,
			TenantID: tenantA, Time: changedAt, Data: canonicalRaw,
		}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(4 * approvalDurabilityDuplicateWindow)
		changedRaw, _ := json.Marshal(projections.ApprovalStatusChanged{
			RequestID: old.ID, IntentDigest: old.IntentDigest,
			Status: store.ApprovalStatusExpired, ChangedAt: changedAt,
		})
		if _, err := log.Append(ctx, events.Event{
			ID: eventID, Type: projections.EventApprovalStatusChanged,
			TenantID: tenantA, Time: changedAt, Data: changedRaw,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, replacementIntent); !errors.Is(err, store.ErrIdempotencyConflict) {
			t.Fatalf("changed retained status = %v, want ErrIdempotencyConflict", err)
		}
		after, err := s.GetOperationApproval(ctx, tenantA, old.ID)
		if err != nil || after.Status != store.ApprovalStatusPending {
			t.Fatalf("changed retained status mutated authority = (%+v, %v)", after, err)
		}
	})
}

func TestOperationApprovalBoundActorMismatchRejected(t *testing.T) {
	const (
		requester = "actor-requester@example.test"
		approver  = "actor-approver@example.test"
		impostor  = "actor-impostor@example.test"
	)
	s := newStore(t)
	resetOrchestratorOperationApprovals(t, s)
	ctx := context.Background()
	log := openLogWithOptions(t, events.WithDuplicateWindowForTesting(approvalDurabilityDuplicateWindow))
	projector := projections.New(s)
	seedApprovalTenant(t, projector, log, tenantA, "approval-actor-binding")
	orch := orchestrator.NewOrchestrator(log, s, nil)
	intent := orchestrator.OperationApprovalIntent{
		ResourceKind: "code_signing", ResourceID: "code-signing:durability/actor", ResourceName: "durability/actor",
		Action: "rotate", Requester: requester, FromState: "version:1", ToState: "version:2",
		Reason: "actor binding", EvidenceRefs: []string{"ticket:actor-binding"},
		RequiredApprovals: 1, TTL: 2 * time.Hour,
	}
	impostorCtx := events.ContextWithActor(ctx, events.Actor{Subject: impostor, Roles: []string{"secret-writer"}})
	if _, err := orch.EnsureOperationApprovalRequest(impostorCtx, tenantA, intent); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("mismatched request actor = %v, want ErrIdempotencyConflict", err)
	}
	requestID := operationApprovalRequestIDForTest(t, tenantA, intent)
	if _, err := s.GetOperationApproval(ctx, tenantA, requestID); !errors.Is(err, store.ErrApprovalRequestNotFound) {
		t.Fatalf("mismatched request actor projected = %v, want not found", err)
	}
	badRequestEvent, found, err := log.EventByID(ctx, requestID)
	if err != nil || !found {
		t.Fatalf("load mismatched request actor event = (found=%t err=%v)", found, err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return projector.ApplyTx(ctx, tx, badRequestEvent)
	}); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("cold projector accepted mismatched request actor = %v", err)
	}
	requesterCtx := events.ContextWithActor(ctx, events.Actor{Subject: requester, Roles: []string{"secret-writer"}})
	if _, err := orch.EnsureOperationApprovalRequest(requesterCtx, tenantA, intent); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("retained mismatched request actor = %v, want ErrIdempotencyConflict", err)
	}

	validIntent := intent
	validIntent.ResourceID = "code-signing:durability/actor-decision"
	validIntent.ResourceName = "durability/actor-decision"
	request, err := orch.EnsureOperationApprovalRequest(requesterCtx, tenantA, validIntent)
	if err != nil {
		t.Fatal(err)
	}
	decision := orchestrator.OperationApprovalDecision{
		RequestID: request.ID, IntentDigest: request.IntentDigest, Approver: approver,
		Decision: store.ApprovalDecisionApprove, Reason: "actor-bound decision",
		ExpectedResourceKind: request.ResourceKind, ExpectedResourceID: request.ResourceID,
		ExpectedAction: request.Action,
	}
	if _, err := orch.RecordOperationApprovalDecision(impostorCtx, tenantA, decision); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("mismatched decision actor = %v, want ErrIdempotencyConflict", err)
	}
	decisionID := projections.OperationApprovalDecisionEventID(tenantA,
		decision.RequestID, decision.IntentDigest, decision.Approver)
	badDecisionEvent, found, err := log.EventByID(ctx, decisionID)
	if err != nil || !found {
		t.Fatalf("load mismatched decision actor event = (found=%t err=%v)", found, err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return projector.ApplyTx(ctx, tx, badDecisionEvent)
	}); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("cold projector accepted mismatched decision actor = %v", err)
	}
	approverCtx := events.ContextWithActor(ctx, events.Actor{Subject: approver, Roles: []string{"secret-approver"}})
	if _, err := orch.RecordOperationApprovalDecision(approverCtx, tenantA, decision); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("retained mismatched decision actor = %v, want ErrIdempotencyConflict", err)
	}
	after, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || after.Status != store.ApprovalStatusPending || after.ApprovalCount != 0 {
		t.Fatalf("mismatched decision actor mutated authority = (%+v, %v)", after, err)
	}
}

func TestReconcileOutboxBackfillsSkippedApprovalNotificationExactlyOnce(t *testing.T) {
	s := newStore(t)
	resetOrchestratorOperationApprovals(t, s)
	ctx := context.Background()
	log := openLog(t)
	projector := projections.New(s)
	seedApprovalTenant(t, projector, log, tenantA, "approval-notification-reconcile")
	request, err := orchestrator.NewOrchestrator(log, s, nil).EnsureOperationApprovalRequest(ctx, tenantA,
		orchestrator.OperationApprovalIntent{
			ResourceKind: "secret", ResourceID: "secret:notification/reconcile", ResourceName: "notification/reconcile",
			Action: "rotate", Requester: "notification-requester", FromState: "version:1", ToState: "version:2",
			Reason: "notify reviewers", EvidenceRefs: []string{"ticket:notification"},
			RequiredApprovals: 1, TTL: time.Hour,
		})
	if err != nil {
		t.Fatal(err)
	}
	requestEvent, found, err := log.EventByID(ctx, request.ID)
	if err != nil || !found {
		t.Fatalf("load request event = (found=%t err=%v)", found, err)
	}
	key := "approval-request:" + request.ID
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, key); got != 0 {
		t.Fatalf("nil-outbox command persisted %d notifications", got)
	}
	// A pre-fix binary skipped this event and advanced its global checkpoint.
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox_reconciliation_checkpoint SET reconciled_seq = $1 WHERE id = 1`, requestEvent.Sequence); err != nil {
		t.Fatal(err)
	}
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	if healed, err := orch.ReconcileOutbox(ctx, log); err != nil || healed != 0 {
		t.Fatalf("pre-upgrade skipped reconcile = (%d, %v), want 0", healed, err)
	}
	// Migration 0151 performs this one-time rewind on upgrade.
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox_reconciliation_checkpoint SET reconciled_seq = 0 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if healed, err := orch.ReconcileOutbox(ctx, log); err != nil || healed != 1 {
		t.Fatalf("rewound approval reconcile = (%d, %v), want 1", healed, err)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, key); got != 1 {
		t.Fatalf("approval notification rows = %d, want 1", got)
	}
	var destination, lane string
	var body []byte
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT destination, effect_lane, payload FROM outbox
		  WHERE tenant_id = $1 AND idempotency_key = $2`, tenantA, key).Scan(&destination, &lane, &body); err != nil {
		t.Fatal(err)
	}
	var alert notify.Alert
	if err := json.Unmarshal(body, &alert); err != nil {
		t.Fatal(err)
	}
	if destination != notify.DestinationApproval || lane != notify.DestinationApproval+":request:"+request.ID ||
		alert.OperationID != "approval-"+request.ID || alert.RequestBinding != request.IntentDigest {
		t.Fatalf("reconciled approval notification = dst=%q lane=%q alert=%+v", destination, lane, alert)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox_reconciliation_checkpoint SET reconciled_seq = 0 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if healed, err := orch.ReconcileOutbox(ctx, log); err != nil || healed != 0 {
		t.Fatalf("second rewound approval reconcile = (%d, %v), want exactly-once 0", healed, err)
	}
}

func seedApprovalTenant(t *testing.T, projector *projections.Projector, log *events.Log, tenantID, name string) {
	t.Helper()
	event, err := log.Append(context.Background(), events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantID, Data: tenantRegisteredJSON(name),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(context.Background(), event); err != nil {
		t.Fatal(err)
	}
}

func oneApprovalEvent(t *testing.T, log *events.Log, tenantID, eventType string) events.Event {
	t.Helper()
	var matches []events.Event
	if err := log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.TenantID == tenantID && event.Type == eventType {
			matches = append(matches, event)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("%s events for %s = %d, want 1", eventType, tenantID, len(matches))
	}
	return matches[0]
}

func countEventsByID(t *testing.T, log *events.Log, eventID string) int {
	t.Helper()
	count := 0
	if err := log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.ID == eventID {
			count++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return count
}

func durabilityStatusIntents() (orchestrator.OperationApprovalIntent, orchestrator.OperationApprovalIntent) {
	old := orchestrator.OperationApprovalIntent{
		ResourceKind: "secret", ResourceID: "secret:durability/status", ResourceName: "durability/status",
		Action: "rotate", Requester: "status-requester", FromState: "version:1", ToState: "version:2",
		Reason: "old status command", EvidenceRefs: []string{"ticket:status-old"},
		RequiredApprovals: 1, TTL: 2 * time.Hour,
	}
	replacement := old
	replacement.ToState = "version:3"
	replacement.Reason = "replacement status command"
	replacement.EvidenceRefs = []string{"ticket:status-replacement"}
	return old, replacement
}

func operationApprovalRequestIDForTest(t *testing.T, tenantID string, intent orchestrator.OperationApprovalIntent) string {
	t.Helper()
	refs := append([]string(nil), intent.EvidenceRefs...)
	sort.Strings(refs)
	basis := struct {
		TenantID          string   `json:"tenant_id"`
		ResourceKind      string   `json:"resource_kind"`
		ResourceID        string   `json:"resource_id"`
		ResourceName      string   `json:"resource_name"`
		Action            string   `json:"action"`
		Requester         string   `json:"requester"`
		FromState         string   `json:"from_state"`
		ToState           string   `json:"to_state"`
		TargetVersion     uint64   `json:"target_version"`
		Reason            string   `json:"reason"`
		EvidenceRefs      []string `json:"evidence_refs"`
		RequiredApprovals int      `json:"required_approvals"`
	}{tenantID, strings.TrimSpace(intent.ResourceKind), strings.TrimSpace(intent.ResourceID),
		strings.TrimSpace(intent.ResourceName), strings.TrimSpace(intent.Action), strings.TrimSpace(intent.Requester),
		strings.TrimSpace(intent.FromState), strings.TrimSpace(intent.ToState), intent.TargetVersion,
		strings.TrimSpace(intent.Reason), refs, intent.RequiredApprovals}
	raw, err := json.Marshal(basis)
	if err != nil {
		t.Fatal(err)
	}
	return uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte("operation-approval\x00"+crypto.SHA256Hex(raw))).String()
}
