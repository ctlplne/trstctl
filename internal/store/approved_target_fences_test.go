// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestApprovedTargetFenceCommitsFirstCanonicalCommandBeforeAppend(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	request := operationApprovalRequest("77000000-0000-4000-8000-000000000801", tenantA)
	request.IntentDigest = "sha256:" + strings.Repeat("a", 64)
	request.RequiredApprovals = 1
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatal(err)
	}
	if err := applyOperationApprovalDecision(ctx, s,
		operationApprovalDecision(request, "bob", "77000000-0000-4000-8000-000000000802")); err != nil {
		t.Fatal(err)
	}
	use := operationApprovalUse(request)
	eventTime := operationApprovalBaseTime.Add(20 * time.Minute)
	firstPayload := []byte(`{"sealed_command":"first-random-ciphertext"}`)
	candidate := store.ApprovedTargetFence{
		TenantID: tenantA, TargetKind: store.ApprovedTargetCodeSigningCommand,
		CommandKey: "codesign-operation-a", RequestBinding: strings.Repeat("b", 64),
		EventID: "77000000-0000-4000-8000-000000000803", EventType: "codesign.commanded",
		SchemaVersion: 2, EventTime: eventTime, Payload: firstPayload,
		SemanticDigest: strings.Repeat("c", 64),
	}
	claimed, created, err := s.ClaimApprovedTargetFence(ctx, candidate, use)
	if err != nil || !created {
		t.Fatalf("first command claim = (created %t, %v)", created, err)
	}
	if !bytes.Equal(claimed.Payload, firstPayload) || !claimed.EventTime.Equal(eventTime) {
		t.Fatalf("canonical first command changed: %+v", claimed)
	}
	approval, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || approval.Status != store.ApprovalStatusConsumed || approval.ConsumedEventID != candidate.EventID {
		t.Fatalf("claim did not durably consume authority before append: %+v err=%v", approval, err)
	}

	// Model a retry after the broker's finite duplicate window: a fresh seal and
	// clock value are generated, but PostgreSQL must return the exact first bytes.
	if _, err := s.SystemPool().Exec(ctx, `UPDATE approved_target_event_fences
		SET created_at = created_at - interval '25 hours', updated_at = updated_at - interval '25 hours'
		WHERE tenant_id = $1 AND target_kind = $2 AND command_key = $3`,
		tenantA, candidate.TargetKind, candidate.CommandKey); err != nil {
		t.Fatal(err)
	}
	retry := candidate
	retry.Payload = []byte(`{"sealed_command":"second-random-ciphertext"}`)
	retry.EventTime = eventTime.Add(25 * time.Hour)
	retry.SemanticDigest = strings.Repeat("d", 64)
	canonical, created, err := s.ClaimApprovedTargetFence(ctx, retry, use)
	if err != nil || created {
		t.Fatalf("late exact retry = (created %t, %v)", created, err)
	}
	if !bytes.Equal(canonical.Payload, firstPayload) || !canonical.EventTime.Equal(eventTime) ||
		canonical.SemanticDigest != candidate.SemanticDigest {
		t.Fatalf("late retry replaced first canonical command: %+v", canonical)
	}

	changedBody := candidate
	changedBody.RequestBinding = strings.Repeat("e", 64)
	if _, _, err := s.ClaimApprovedTargetFence(ctx, changedBody, use); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed request body claim = %v, want ErrIdempotencyConflict", err)
	}
	if _, err := s.GetApprovedTargetFence(ctx, tenantB, candidate.TargetKind, candidate.CommandKey); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("tenant B read tenant A fence = %v, want pgx.ErrNoRows", err)
	}
}

func TestApprovedTargetFenceReconsumesAuthorityRebuiltBeforeRetainedTarget(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	request := operationApprovalRequest("77000000-0000-4000-8000-000000000804", tenantA)
	request.IntentDigest = "sha256:" + strings.Repeat("e", 64)
	request.RequiredApprovals = 1
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatal(err)
	}
	if err := applyOperationApprovalDecision(ctx, s,
		operationApprovalDecision(request, "bob", "77000000-0000-4000-8000-000000000805")); err != nil {
		t.Fatal(err)
	}
	use := operationApprovalUse(request)
	candidate := store.ApprovedTargetFence{
		TenantID: tenantA, TargetKind: store.ApprovedTargetCodeSigningCommand,
		CommandKey: "codesign-full-restore", RequestBinding: strings.Repeat("f", 64),
		EventID: "77000000-0000-4000-8000-000000000806", EventType: "codesign.commanded",
		SchemaVersion: 2, EventTime: operationApprovalBaseTime.Add(20 * time.Minute),
		Payload: []byte(`{"sealed_command":"full-restore"}`), SemanticDigest: strings.Repeat("9", 64),
	}
	if _, _, err := s.ClaimApprovedTargetFence(ctx, candidate, use); err != nil {
		t.Fatalf("claim target before append: %v", err)
	}

	// A full read-model rebuild replays request and decision history before the
	// retained target event. The independent fence survives PostgreSQL restore,
	// while the rebuilt request is approved again until that exact event projects.
	if _, err := s.SystemPool().Exec(ctx, `UPDATE operation_approval_requests
		SET status = 'approved', consumed_at = NULL, consumed_event_id = NULL
		WHERE tenant_id = $1 AND id = $2`, tenantA, request.ID); err != nil {
		t.Fatal(err)
	}
	err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		locked, rebuiltUse, privacyRewritten, err := s.LockApprovedTargetFenceTx(
			ctx, tx, tenantA, candidate.TargetKind, candidate.CommandKey,
		)
		if err != nil {
			return err
		}
		if privacyRewritten || !reflect.DeepEqual(rebuiltUse, use) {
			t.Fatalf("rebuilt fence use = privacy %t use %+v, want exact %+v",
				privacyRewritten, rebuiltUse, use)
		}
		return s.ConsumeOperationApprovalTx(
			ctx, tx, tenantA, rebuiltUse, locked.EventID, locked.EventTime,
		)
	})
	if err != nil {
		t.Fatalf("reconsume rebuilt approval through retained exact target: %v", err)
	}
	rebuilt, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || rebuilt.Status != store.ApprovalStatusConsumed || rebuilt.ConsumedEventID != candidate.EventID {
		t.Fatalf("rebuilt authority after target = %+v err=%v", rebuilt, err)
	}
}

func TestApprovedTargetFenceRejectsAnotherApprovalAndCompletesOnlyExactTarget(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	request := operationApprovalRequest("77000000-0000-4000-8000-000000000811", tenantA)
	request.IntentDigest = "sha256:" + strings.Repeat("1", 64)
	request.RequiredApprovals = 1
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatal(err)
	}
	if err := applyOperationApprovalDecision(ctx, s,
		operationApprovalDecision(request, "bob", "77000000-0000-4000-8000-000000000812")); err != nil {
		t.Fatal(err)
	}
	use := operationApprovalUse(request)
	candidate := store.ApprovedTargetFence{
		TenantID: tenantA, TargetKind: store.ApprovedTargetEphemeralCertificate,
		CommandKey: strings.Repeat("2", 64), RequestBinding: strings.Repeat("3", 64),
		EventID: "77000000-0000-4000-8000-000000000813", EventType: "certificate.recorded",
		SchemaVersion: 3, EventTime: operationApprovalBaseTime.Add(20 * time.Minute),
		Payload: []byte(`{"certificate_der":"public"}`), SemanticDigest: strings.Repeat("4", 64),
	}
	if _, _, err := s.ClaimApprovedTargetFence(ctx, candidate, use); err != nil {
		t.Fatal(err)
	}

	other := request
	other.ID = "77000000-0000-4000-8000-000000000814"
	other.IntentDigest = "sha256:" + strings.Repeat("5", 64)
	if err := applyOperationApprovalRequest(ctx, s, other); err != nil {
		t.Fatal(err)
	}
	if err := applyOperationApprovalDecision(ctx, s,
		operationApprovalDecision(other, "carol", "77000000-0000-4000-8000-000000000815")); err != nil {
		t.Fatal(err)
	}
	otherUse := operationApprovalUse(other)
	otherCandidate := candidate
	otherCandidate.EventID = "77000000-0000-4000-8000-000000000816"
	if _, _, err := s.ClaimApprovedTargetFence(ctx, otherCandidate, otherUse); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("different approval reused command fence = %v, want ErrIdempotencyConflict", err)
	}
	otherApproval, err := s.GetOperationApproval(ctx, tenantA, other.ID)
	if err != nil || otherApproval.Status != store.ApprovalStatusApproved {
		t.Fatalf("conflicting claim spent other approval: %+v err=%v", otherApproval, err)
	}

	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, _, _, err := s.LockApprovedTargetFenceTx(ctx, tx, tenantA, candidate.TargetKind, candidate.CommandKey); err != nil {
			return err
		}
		return s.CompleteApprovedTargetFenceTx(ctx, tx, tenantA, candidate.TargetKind, candidate.CommandKey,
			candidate.EventID, candidate.EventType, candidate.SchemaVersion, candidate.EventTime,
			[]byte(strings.Repeat("9", 64)))
	})
	if !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("wrong semantic target completed fence = %v, want ErrIdempotencyConflict", err)
	}
	if _, err := s.GetApprovedTargetFence(ctx, tenantA, candidate.TargetKind, candidate.CommandKey); err != nil {
		t.Fatalf("wrong target deleted fence: %v", err)
	}
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.CompleteApprovedTargetFenceTx(ctx, tx, tenantA, candidate.TargetKind, candidate.CommandKey,
			candidate.EventID, candidate.EventType, candidate.SchemaVersion, candidate.EventTime,
			[]byte(candidate.SemanticDigest))
	})
	if err != nil {
		t.Fatalf("complete exact target: %v", err)
	}
	if _, err := s.GetApprovedTargetFence(ctx, tenantA, candidate.TargetKind, candidate.CommandKey); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("completed fence still present = %v", err)
	}
}

func TestApprovedTargetFencePrivacyRecoveryRequiresConsumedEventAndPlaceholder(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	request := operationApprovalRequest("77000000-0000-4000-8000-000000000821", tenantA)
	request.IntentDigest = "sha256:" + strings.Repeat("6", 64)
	request.RequiredApprovals = 1
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatal(err)
	}
	if err := applyOperationApprovalDecision(ctx, s,
		operationApprovalDecision(request, "bob", "77000000-0000-4000-8000-000000000822")); err != nil {
		t.Fatal(err)
	}
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	candidate := store.ApprovedTargetFence{
		TenantID: tenantA, TargetKind: store.ApprovedTargetCodeSigningCommand,
		CommandKey: "privacy-recovery", RequestBinding: strings.Repeat("7", 64),
		EventID: "77000000-0000-4000-8000-000000000823", EventType: "codesign.commanded",
		SchemaVersion: 2, EventTime: operationApprovalBaseTime.Add(20 * time.Minute),
		Payload: []byte(`{"approval":"exact-first-command"}`), SemanticDigest: strings.Repeat("8", 64),
	}
	if _, _, err := s.ClaimApprovedTargetFence(ctx, candidate, use); err != nil {
		t.Fatalf("claim exact command: %v", err)
	}

	// Clearing reviewer text is not enough: an ordinary requester is not an
	// authorized privacy rewrite, even though this approval is already consumed.
	if _, err := s.SystemPool().Exec(ctx, `UPDATE operation_approval_requests
		SET reason = '', evidence_refs = '[]'::jsonb
		WHERE tenant_id = $1 AND id = $2`, tenantA, request.ID); err != nil {
		t.Fatal(err)
	}
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, _, _, err := s.LockApprovedTargetFenceTx(ctx, tx, tenantA, candidate.TargetKind, candidate.CommandKey)
		return err
	})
	if !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("ordinary requester with cleared evidence locked fence = %v, want ErrApprovalDrifted", err)
	}

	placeholder := privacy.Placeholder(privacy.SubjectRef(tenantA, request.Requester))
	if _, err := s.SystemPool().Exec(ctx, `UPDATE operation_approval_requests
		SET requester = $3, resource_kind = $3, resource_id = $3, resource_name = $3, action = $3,
		    from_state = $3, to_state = $3
		WHERE tenant_id = $1 AND id = $2`, tenantA, request.ID, placeholder); err != nil {
		t.Fatal(err)
	}
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		locked, recoveredUse, privacyRewritten, err := s.LockApprovedTargetFenceTx(ctx, tx,
			tenantA, candidate.TargetKind, candidate.CommandKey)
		if err != nil {
			return err
		}
		if !privacyRewritten || recoveredUse.Requester != placeholder ||
			recoveredUse.Reason != "" || len(recoveredUse.EvidenceRefs) != 0 {
			t.Fatalf("privacy recovery = rewritten %t use %+v", privacyRewritten, recoveredUse)
		}
		encodedUse, err := json.Marshal(recoveredUse)
		if err != nil {
			return err
		}
		var replayedUse store.OperationApprovalUse
		if err := json.Unmarshal(encodedUse, &replayedUse); err != nil {
			return err
		}
		if err := s.ConsumeOperationApprovalTx(
			ctx, tx, tenantA, replayedUse, locked.EventID, locked.EventTime,
		); !errors.Is(err, store.ErrApprovalDrifted) {
			t.Fatalf("serialized privacy recovery capability error = %v, want ErrApprovalDrifted", err)
		}
		if err := s.ConsumeOperationApprovalTx(
			ctx, tx, tenantA, recoveredUse, "77000000-0000-4000-8000-000000000824", locked.EventTime,
		); !errors.Is(err, store.ErrApprovalDrifted) {
			t.Fatalf("privacy recovery for another event error = %v, want ErrApprovalDrifted", err)
		}
		return s.ConsumeOperationApprovalTx(ctx, tx, tenantA, recoveredUse,
			locked.EventID, locked.EventTime)
	})
	if err != nil {
		t.Fatalf("exact consumed-event retention recovery: %v", err)
	}
}

func TestApprovedTargetFenceUsesEventHistoryPrivacyRewriteAndDefersRetention(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	const subject = "alice.fence@example.com"
	request := operationApprovalRequest("77000000-0000-4000-8000-000000000831", tenantA)
	request.IntentDigest = "sha256:" + strings.Repeat("a", 64)
	request.Requester = subject
	request.Reason = "requested by " + subject
	request.EvidenceRefs = []string{"ticket:" + subject}
	request.RequiredApprovals = 1
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatal(err)
	}
	if err := applyOperationApprovalDecision(ctx, s,
		operationApprovalDecision(request, "bob", "77000000-0000-4000-8000-000000000832")); err != nil {
		t.Fatal(err)
	}
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(projections.CertificateRecorded{
		ID:      "77000000-0000-4000-8000-000000000835",
		Subject: "CN=" + subject, SANs: []string{subject}, Issuer: "privacy-test-ca",
		Serial: "01", Fingerprint: strings.Repeat("d", 64), KeyAlgorithm: "ECDSA-P256",
		Source: "issued", Approval: &use,
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate := store.ApprovedTargetFence{
		TenantID: tenantA, TargetKind: store.ApprovedTargetEphemeralCertificate,
		CommandKey: "privacy-payload", RequestBinding: strings.Repeat("b", 64),
		EventID: "77000000-0000-4000-8000-000000000833", EventType: projections.EventCertificateRecorded,
		SchemaVersion: projections.CertificateApprovalEventSchemaVersion, EventTime: operationApprovalBaseTime.Add(20 * time.Minute),
		Actor: &events.Actor{
			Subject: "release-admin",
			Roles:   []string{"team:" + subject, "release", subject + ":delegate", "release"},
		},
		Payload: payload, SemanticDigest: strings.Repeat("c", 64),
	}
	if _, _, err := s.ClaimApprovedTargetFence(ctx, candidate, use); err != nil {
		t.Fatal(err)
	}

	// A security command that still needs projection is a bounded retention hold:
	// clearing its approval first would destroy the proof needed to heal it.
	now := time.Now().UTC()
	if _, err := s.SystemPool().Exec(ctx, `UPDATE operation_approval_requests
		SET updated_at = $3
		WHERE tenant_id = $1 AND id = $2`, tenantA, request.ID, now.Add(-500*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	run, err := s.SelectPrivacyRetention(ctx, tenantA,
		"77000000-0000-4000-8000-000000000834", privacy.DefaultRetentionPolicy(), now)
	if err != nil {
		t.Fatal(err)
	}
	if run.Counts["operation_approval_requests"] != 0 {
		t.Fatalf("retention selected fenced approval = %+v", run.Counts)
	}

	changed, err := s.PseudonymizeApprovedTargetFences(ctx, tenantA, subject)
	if err != nil || changed != 1 {
		t.Fatalf("pseudonymize surviving fence = changed %d err=%v", changed, err)
	}
	rewritten, err := s.GetApprovedTargetFence(ctx, tenantA, candidate.TargetKind, candidate.CommandKey)
	if err != nil {
		t.Fatal(err)
	}
	placeholder := privacy.Placeholder(privacy.SubjectRef(tenantA, subject))
	if bytes.Contains(rewritten.Payload, []byte(subject)) || !bytes.Contains(rewritten.Payload, []byte(placeholder)) ||
		strings.Contains(rewritten.Approval.Reason, subject) ||
		len(rewritten.Approval.EvidenceRefs) != 1 || strings.Contains(rewritten.Approval.EvidenceRefs[0], subject) {
		t.Fatalf("pseudonymized fence retained raw subject: %+v payload=%s", rewritten, rewritten.Payload)
	}
	wantActor := &events.Actor{
		Subject: "release-admin",
		Roles:   []string{"team:" + placeholder, "release", placeholder + ":delegate", "release"},
	}
	if !reflect.DeepEqual(rewritten.Actor, wantActor) {
		t.Fatalf("pseudonymized fence actor = %+v, want ordered/cardinality-preserving %+v", rewritten.Actor, wantActor)
	}
	var retained struct {
		Approval *store.OperationApprovalUse `json:"approval"`
	}
	if err := json.Unmarshal(rewritten.Payload, &retained); err != nil || retained.Approval == nil {
		t.Fatalf("decode rewritten approval: %+v err=%v", retained, err)
	}
	current := use
	current.Requester = placeholder
	current.Reason = ""
	current.EvidenceRefs = []string{}
	if err := store.ValidateApprovedTargetPrivacyRewrite(tenantA, use, current, *retained.Approval); err != nil {
		t.Fatalf("event-history-equivalent fence rewrite refused: %v", err)
	}
	elementCleared := use
	elementCleared.Requester = placeholder
	elementCleared.Reason = ""
	elementCleared.EvidenceRefs = make([]string, len(use.EvidenceRefs))
	if err := store.ValidateApprovedTargetPrivacyRewrite(tenantA, use, current, elementCleared); err != nil {
		t.Fatalf("cardinality-preserving event evidence rewrite refused: %v", err)
	}
	originalWithOpaque := use
	originalWithOpaque.EvidenceRefs = append(append([]string(nil), use.EvidenceRefs...), "sha256:opaque-attempt-binding")
	retainedWithOpaque := elementCleared
	retainedWithOpaque.EvidenceRefs = []string{"", "sha256:opaque-attempt-binding"}
	if err := store.ValidateApprovedTargetPrivacyRewrite(
		tenantA, originalWithOpaque, current, retainedWithOpaque,
	); err != nil {
		t.Fatalf("opaque evidence binding did not survive privacy recovery: %v", err)
	}
	hostileClearedOpaque := retainedWithOpaque
	hostileClearedOpaque.EvidenceRefs = []string{"", ""}
	if err := store.ValidateApprovedTargetPrivacyRewrite(
		tenantA, originalWithOpaque, current, hostileClearedOpaque,
	); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("cleared opaque evidence error = %v, want ErrApprovalDrifted", err)
	}
	if err := store.ValidateApprovedTargetActorPrivacyRewrite(
		tenantA, candidate.Actor, current.Requester, rewritten.Actor, subject,
	); err != nil {
		t.Fatalf("event-history-equivalent actor-role rewrite refused: %v", err)
	}
	if err := store.ValidateApprovedTargetActorPrivacyRewrite(
		tenantA, candidate.Actor, current.Requester, candidate.Actor, subject,
	); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("unchanged raw actor roles error = %v, want ErrApprovalDrifted", err)
	}
	hostile := *rewritten.Actor
	hostile.Roles = append([]string(nil), rewritten.Actor.Roles...)
	hostile.Roles[0], hostile.Roles[1] = hostile.Roles[1], hostile.Roles[0]
	if err := store.ValidateApprovedTargetActorPrivacyRewrite(
		tenantA, candidate.Actor, current.Requester, &hostile, subject,
	); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("reordered privacy actor roles error = %v, want ErrApprovalDrifted", err)
	}
}
