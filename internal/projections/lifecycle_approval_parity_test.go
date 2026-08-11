// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type approvalLifecyclePayload struct {
	IdentityID     string                                  `json:"identity_id"`
	From           string                                  `json:"from"`
	To             string                                  `json:"to"`
	Reason         string                                  `json:"reason,omitempty"`
	IdempotencyKey string                                  `json:"idempotency_key,omitempty"`
	SubjectCSRPEM  string                                  `json:"subject_csr_pem,omitempty"`
	SideEffect     *approvalLifecycleSideEffect            `json:"side_effect,omitempty"`
	Approval       *store.OperationApprovalUse             `json:"approval,omitempty"`
	Issuance       *store.OperationApprovalIssuanceBinding `json:"issuance,omitempty"`
}

type approvalLifecycleSideEffect struct {
	Destination    string `json:"destination"`
	IdempotencyKey string `json:"idempotency_key"`
	Payload        []byte `json:"payload,omitempty"`
}

func marshalApprovalLifecyclePayload(t *testing.T, payload approvalLifecyclePayload) []byte {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func approvedIdentityLifecycleUse(
	t *testing.T,
	orch *orchestrator.Orchestrator,
	tenantID, identityID, identityName string,
) store.OperationApprovalUse {
	t.Helper()
	request, err := orch.EnsureOperationApprovalRequest(context.Background(), tenantID, orchestrator.OperationApprovalIntent{
		ResourceKind: "identity", ResourceID: identityID, ResourceName: identityName,
		Action: "issue", Requester: "requester@example.test",
		FromState: string(orchestrator.StateRequested), ToState: string(orchestrator.StateIssued),
		TargetVersion: 0, Reason: "approved lifecycle parity proof",
		EvidenceRefs: []string{
			"idempotency-key-sha256:" + crypto.SHA256Hex([]byte("lifecycle-parity")),
		},
		RequiredApprovals: 1, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("ensure lifecycle approval request: %v", err)
	}
	request, err = orch.RecordOperationApprovalDecision(context.Background(), tenantID, orchestrator.OperationApprovalDecision{
		RequestID: request.ID, IntentDigest: request.IntentDigest,
		Approver: "approver@example.test", Decision: store.ApprovalDecisionApprove,
		ExpectedResourceKind: "identity", ExpectedResourceID: identityID, ExpectedAction: "issue",
	})
	if err != nil {
		t.Fatalf("approve lifecycle request: %v", err)
	}
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		t.Fatalf("build lifecycle approval use: %v", err)
	}
	return use
}

func TestLifecycleApprovalSchemaPayloadParityFailsBeforeMutation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		version  int
		use      *store.OperationApprovalUse
		issuance *store.OperationApprovalIssuanceBinding
		want     string
	}{
		{name: "v4 requires approval", version: projections.LifecycleApprovalEventSchemaVersion, want: "approval payload/schema mismatch"},
		{name: "v3 cannot smuggle approval", version: projections.LifecycleSideEffectEventSchemaVersion, use: &store.OperationApprovalUse{
			RequestID: "77000000-0000-4000-8000-000000000701", IntentDigest: "sha256:smuggled",
		}, want: "approval payload/schema mismatch"},
		{name: "v5 requires issuance", version: projections.LifecycleIssuanceEventSchemaVersion, want: "issuance payload/schema mismatch"},
		{name: "v4 cannot smuggle outer issuance", version: projections.LifecycleApprovalEventSchemaVersion,
			use:      &store.OperationApprovalUse{RequestID: "77000000-0000-4000-8000-000000000701", IntentDigest: "sha256:smuggled"},
			issuance: &store.OperationApprovalIssuanceBinding{RequestedTTLSeconds: 60, EffectiveTTLSeconds: 60},
			want:     "approval payload/schema mismatch"},
		{name: "v3 cannot smuggle issuance", version: projections.LifecycleSideEffectEventSchemaVersion,
			issuance: &store.OperationApprovalIssuanceBinding{RequestedTTLSeconds: 60, EffectiveTTLSeconds: 60},
			want:     "issuance payload/schema mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			seedIdentity(t, s, tenantA)
			event := events.Event{
				ID: "77000000-0000-4000-8000-000000000702", Type: projections.EventIdentityIssued,
				TenantID: tenantA, SchemaVersion: tc.version, Time: time.Now().UTC(), Sequence: 1,
				Data: marshalApprovalLifecyclePayload(t, approvalLifecyclePayload{
					IdentityID: idIdentity, From: string(orchestrator.StateRequested),
					To: string(orchestrator.StateIssued), Approval: tc.use, Issuance: tc.issuance,
				}),
			}
			err := projections.New(s).Apply(context.Background(), event)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("schema/payload mismatch error = %v", err)
			}
			identity, getErr := s.GetIdentity(context.Background(), tenantA, idIdentity)
			if getErr != nil || identity.Status != string(orchestrator.StateRequested) {
				t.Fatalf("mismatch mutated identity = (%+v, %v)", identity, getErr)
			}
		})
	}
}

func TestLifecycleApprovalSameEventReplayCannotRetargetIdentityAfterDedupWindow(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	owner, err := orch.CreateOwner(ctx, tenantA, "workload", "lifecycle-owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identityA, err := orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "approved.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	identityB, err := orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "unapproved.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	use := approvedIdentityLifecycleUse(t, orch, tenantA, identityA.ID, identityA.Name)
	if err := orch.TransitionWithSubjectCSRAndApproval(ctx, tenantA, identityA.ID,
		orchestrator.StateIssued, "approved lifecycle parity proof", "lifecycle-parity", "", use); err != nil {
		t.Fatalf("apply approved lifecycle event: %v", err)
	}
	consumed, err := s.GetOperationApproval(ctx, tenantA, use.RequestID)
	if err != nil || consumed.Status != store.ApprovalStatusConsumed || consumed.ConsumedEventID == "" {
		t.Fatalf("consumed request = (%+v, %v)", consumed, err)
	}

	// JetStream only deduplicates a message ID inside its configured 24-hour
	// window. Model the same ID being accepted after that window: projection must
	// validate the payload again instead of treating consumed_event_id as permission
	// to apply different identity bytes.
	replayed := events.Event{
		ID: consumed.ConsumedEventID, Type: projections.EventIdentityIssued,
		TenantID: tenantA, SchemaVersion: projections.LifecycleApprovalEventSchemaVersion,
		Time: time.Now().UTC().Add(25 * time.Hour), Sequence: 999,
		Data: marshalApprovalLifecyclePayload(t, approvalLifecyclePayload{
			IdentityID: identityB.ID, From: string(orchestrator.StateRequested),
			To: string(orchestrator.StateIssued), Reason: "approved lifecycle parity proof", Approval: &use,
		}),
	}
	if err := projections.New(s).Apply(ctx, replayed); err == nil || !strings.Contains(err.Error(), "approval target mismatch") {
		t.Fatalf("retargeted same-event replay error = %v", err)
	}
	unchanged, err := s.GetIdentity(ctx, tenantA, identityB.ID)
	if err != nil || unchanged.Status != string(orchestrator.StateRequested) {
		t.Fatalf("same-event replay mutated unapproved identity = (%+v, %v)", unchanged, err)
	}
}

func TestLifecycleApprovalMismatchFailsColdRebuildBeforeConsumeOrMutation(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	owner, err := orch.CreateOwner(ctx, tenantA, "workload", "rebuild-owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identityA, err := orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "reviewed.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	identityB, err := orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "rebuild-target.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	use := approvedIdentityLifecycleUse(t, orch, tenantA, identityA.ID, identityA.Name)
	malformed, err := log.Append(ctx, events.Event{
		ID: "77000000-0000-4000-8000-000000000703", Type: projections.EventIdentityIssued,
		TenantID: tenantA, SchemaVersion: projections.LifecycleApprovalEventSchemaVersion,
		Data: marshalApprovalLifecyclePayload(t, approvalLifecyclePayload{
			IdentityID: identityB.ID, From: string(orchestrator.StateRequested),
			To: string(orchestrator.StateIssued), Reason: "approved lifecycle parity proof", Approval: &use,
		}),
	})
	if err != nil {
		t.Fatalf("append malformed lifecycle event: %v", err)
	}
	if err := projections.New(s).Rebuild(ctx, log); err == nil || !strings.Contains(err.Error(), "approval target mismatch") {
		t.Fatalf("cold rebuild mismatch at seq %d = %v", malformed.Sequence, err)
	}
	request, err := s.GetOperationApproval(ctx, tenantA, use.RequestID)
	if err != nil || request.Status != store.ApprovalStatusApproved || request.ConsumedEventID != "" {
		t.Fatalf("cold rebuild consumed mismatched authority = (%+v, %v)", request, err)
	}
	unchanged, err := s.GetIdentity(ctx, tenantA, identityB.ID)
	if err != nil || unchanged.Status != string(orchestrator.StateRequested) {
		t.Fatalf("cold rebuild mutated mismatched identity = (%+v, %v)", unchanged, err)
	}
}

func TestLifecycleApprovalRejectsNestedCommandCopyBeforeConsume(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	owner, err := orch.CreateOwner(ctx, tenantA, "workload", "nested-copy-owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "nested-copy.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	use := approvedIdentityLifecycleUse(t, orch, tenantA, identity.ID, identity.Name)
	eventID := projections.LifecycleApprovalEventID(tenantA, use)
	event := events.Event{
		ID: eventID, Type: projections.EventIdentityIssued,
		TenantID: tenantA, SchemaVersion: projections.LifecycleApprovalEventSchemaVersion,
		Time: time.Now().UTC(), Sequence: 700,
		Data: marshalApprovalLifecyclePayload(t, approvalLifecyclePayload{
			IdentityID: identity.ID, From: string(orchestrator.StateRequested),
			To: string(orchestrator.StateIssued), Reason: use.Reason,
			IdempotencyKey: "lifecycle-parity", Approval: &use,
			SideEffect: &approvalLifecycleSideEffect{
				Destination: "ca.issue", IdempotencyKey: "transition:lifecycle-parity",
				Payload: []byte(`{"poison":"second command"}`),
			},
		}),
	}
	err = projections.New(s).Apply(ctx, event)
	if err == nil || !strings.Contains(err.Error(), "side-effect is not derived") {
		t.Fatalf("nested v4 command copy error = %v", err)
	}
	request, err := s.GetOperationApproval(ctx, tenantA, use.RequestID)
	if err != nil || request.Status != store.ApprovalStatusApproved || request.ConsumedEventID != "" {
		t.Fatalf("nested-copy poison consumed authority = (%+v, %v)", request, err)
	}
	unchanged, err := s.GetIdentity(ctx, tenantA, identity.ID)
	if err != nil || unchanged.Status != string(orchestrator.StateRequested) {
		t.Fatalf("nested-copy poison mutated identity = (%+v, %v)", unchanged, err)
	}
}

func TestLifecycleApprovalPhysicalDuplicateMustMatchCurrentEventSequence(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	owner, err := orch.CreateOwner(ctx, tenantA, "workload", "duplicate-sequence-owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "duplicate-sequence.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	use := approvedIdentityLifecycleUse(t, orch, tenantA, identity.ID, identity.Name)
	if err := orch.TransitionWithSubjectCSRAndApproval(ctx, tenantA, identity.ID,
		orchestrator.StateIssued, use.Reason, "lifecycle-parity", "", use); err != nil {
		t.Fatalf("commit canonical lifecycle: %v", err)
	}
	request, err := s.GetOperationApproval(ctx, tenantA, use.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	var canonical events.Event
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.ID == request.ConsumedEventID {
			canonical = event
		}
		return nil
	}); err != nil || canonical.ID == "" {
		t.Fatalf("load canonical lifecycle = (%+v, %v)", canonical, err)
	}
	duplicate := canonical
	duplicate.Sequence += 1000
	duplicate.Time = duplicate.Time.Add(25 * time.Hour)
	if err := projections.New(s).Apply(ctx, duplicate); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("same-ID physical duplicate at new sequence = %v, want ErrApprovalDrifted", err)
	}
	wrongType := canonical
	wrongType.Type = projections.EventIdentityRevoked
	if err := projections.New(s).Apply(ctx, wrongType); err == nil || !strings.Contains(err.Error(), "edge/action mismatch") {
		t.Fatalf("same-ID replay with changed event type = %v, want edge/action mismatch", err)
	}
	after, err := s.GetIdentity(ctx, tenantA, identity.ID)
	if err != nil || after.Status != string(orchestrator.StateIssued) {
		t.Fatalf("poisoned duplicate changed identity = (%+v, %v)", after, err)
	}
}
