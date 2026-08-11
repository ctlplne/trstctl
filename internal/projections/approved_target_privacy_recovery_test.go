// SPDX-License-Identifier: MPL-2.0

package projections_test

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

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestApprovedCodeSigningFenceProjectsAfterAuthorizedHistoryPrivacyRewrite(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.SystemPool().Exec(ctx, `TRUNCATE approved_target_event_fences,
		code_signing_operations, outbox, operation_approval_decisions,
		operation_approval_requests RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "privacy-fence"}); err != nil {
		t.Fatal(err)
	}

	const (
		subject        = "release.bot@example.com"
		idempotencyKey = "privacy-fenced/" + subject + "/code-signing"
		requestID      = "77100000-0000-4000-8000-000000000901"
		decisionID     = "77100000-0000-4000-8000-000000000902"
	)
	requestHash := crypto.SHA256Hex([]byte("exact sealed code-signing command"))
	resourceID := store.CodeSigningApprovalResourceID(requestHash, idempotencyKey)
	now := time.Now().UTC().Truncate(time.Microsecond)
	request := store.OperationApprovalRequest{
		ID: requestID, TenantID: tenantA, IntentDigest: "sha256:" + strings.Repeat("a", 64),
		ResourceKind: "code_signing", ResourceID: resourceID, ResourceName: "release-key",
		Action: "sign", Requester: subject, Reason: "authorize " + subject,
		EvidenceRefs: []string{"ticket:" + subject}, RequiredApprovals: 1,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyOperationApprovalRequestedTx(ctx, tx, request)
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyOperationApprovalDecisionTx(ctx, tx, store.OperationApprovalDecision{
			TenantID: tenantA, RequestID: request.ID, IntentDigest: request.IntentDigest,
			Approver: "security-approver", Decision: store.ApprovalDecisionApprove,
			EventID: decisionID, DecidedAt: now.Add(time.Minute),
		})
	}); err != nil {
		t.Fatal(err)
	}
	approved, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	use, err := store.OperationApprovalUseFromRequest(approved)
	if err != nil {
		t.Fatal(err)
	}
	operationID := projections.CodeSigningOperationID(tenantA, idempotencyKey)
	keyRef := store.CodeSigningIdempotencyKeyRef(idempotencyKey)
	requestBinding := projections.CodeSigningRequestBinding(requestHash, idempotencyKey)
	payload := projections.CodeSigningCommanded{
		OperationID: operationID, IdempotencyKeyRef: keyRef, RequestBinding: requestBinding,
		Mode: "key", RequestHash: requestHash,
		SealedCommand: []byte("already-tenant-sealed"), Approval: &use,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{
		ID:   projections.CodeSigningApprovalEventID(tenantA, operationID),
		Type: projections.EventCodeSigningCommanded, TenantID: tenantA,
		Time: now.Add(2 * time.Minute), SchemaVersion: projections.CodeSigningPrivacySafeEventSchemaVersion,
		Data: raw, Actor: &events.Actor{
			Subject: subject,
			Roles:   []string{"release", "delegate:" + subject, subject + ":sign", "release"},
		},
	}
	semantic, err := projections.CodeSigningCommandSemanticDigest(event, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := s.ClaimApprovedTargetFence(ctx, store.ApprovedTargetFence{
		TenantID: tenantA, TargetKind: store.ApprovedTargetCodeSigningCommand,
		CommandKey: operationID, RequestBinding: requestBinding,
		EventID: event.ID, EventType: event.Type, SchemaVersion: event.SchemaVersion,
		EventTime: event.Time, Actor: event.Actor, Payload: event.Data, SemanticDigest: semantic,
	}, use); err != nil || !created {
		t.Fatalf("claim first command = created %t err=%v", created, err)
	}
	if bytes.Contains(raw, []byte(idempotencyKey)) {
		t.Fatalf("privacy-safe canonical payload retained raw idempotency key: %s", raw)
	}

	if changed, err := s.PseudonymizeApprovedTargetFences(ctx, tenantA, subject); err != nil || changed != 1 {
		t.Fatalf("rewrite durable fence = changed %d err=%v", changed, err)
	}
	rewritten, changed := events.PseudonymizeDataForSubject(event.Data, tenantA, subject)
	if !changed {
		t.Fatal("canonical event payload did not contain privacy subject")
	}
	event.Data = rewritten
	placeholder := privacy.Placeholder(privacy.SubjectRef(tenantA, subject))
	event.Actor, changed = events.PseudonymizeActorForSubject(event.Actor, tenantA, subject)
	if !changed {
		t.Fatal("canonical event actor did not contain privacy subject")
	}
	if _, err := s.SystemPool().Exec(ctx, `UPDATE operation_approval_requests
		SET requester = $3, reason = '', evidence_refs = '[]'::jsonb
		WHERE tenant_id = $1 AND id = $2`, tenantA, request.ID, placeholder); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(event.Data, []byte(subject)) {
		t.Fatalf("rewritten canonical event retained %q: %s", subject, event.Data)
	}
	wantRoles := []string{"release", "delegate:" + placeholder, placeholder + ":sign", "release"}
	if !reflect.DeepEqual(event.Actor.Roles, wantRoles) {
		t.Fatalf("rewritten canonical roles = %v, want %v", event.Actor.Roles, wantRoles)
	}

	// Semantic comparison intentionally normalizes privacy fields, so this
	// hostile evidence change reaches the exact privacy-shape validator and must
	// still fail without consuming/deleting the durable fence.
	hostile := event
	var hostilePayload projections.CodeSigningCommanded
	if err := json.Unmarshal(hostile.Data, &hostilePayload); err != nil {
		t.Fatal(err)
	}
	hostilePayload.Approval.EvidenceRefs = []string{"hostile:replacement"}
	hostile.Data, err = json.Marshal(hostilePayload)
	if err != nil {
		t.Fatal(err)
	}
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return projections.New(s).ApplyTx(ctx, tx, hostile)
	})
	if !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("hostile privacy-shaped target = %v, want ErrApprovalDrifted", err)
	}
	if _, found, err := s.CodeSigningOperationByID(ctx, tenantA, operationID); err != nil || found {
		t.Fatalf("hostile target projected operation = found %t err=%v", found, err)
	}

	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return projections.New(s).ApplyTx(ctx, tx, event)
	}); err != nil {
		t.Fatalf("project authorized privacy-rewritten target: %v", err)
	}
	op, found, err := s.CodeSigningOperationByID(ctx, tenantA, operationID)
	if err != nil || !found || op.SourceEventID != event.ID ||
		op.ApprovalRequestID != request.ID || op.IdempotencyKey != keyRef {
		t.Fatalf("privacy-recovered operation = found %t op=%+v err=%v", found, op, err)
	}
	if _, err := s.GetApprovedTargetFence(ctx, tenantA,
		store.ApprovedTargetCodeSigningCommand, operationID); !store.IsNotFound(err) {
		t.Fatalf("completed privacy fence remains: %v", err)
	}
}
