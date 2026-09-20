// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

var operationApprovalBaseTime = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

func newOperationApprovalStore(t *testing.T) *store.Store {
	t.Helper()
	s := newStore(t)
	reset := func() {
		t.Helper()
		if _, err := s.SystemPool().Exec(context.Background(),
			`TRUNCATE approved_target_event_fences, operation_approval_decisions, operation_approval_requests`); err != nil {
			t.Fatalf("truncate operation approvals: %v", err)
		}
	}
	reset()
	t.Cleanup(reset)
	seedTwoTenants(t, s)
	return s
}

func operationApprovalRequest(id, tenantID string) store.OperationApprovalRequest {
	return store.OperationApprovalRequest{
		ID: id, TenantID: tenantID, IntentDigest: "sha256:immutable-intent-a",
		ResourceKind: "identity", ResourceID: "identity/checkout", ResourceName: "checkout",
		Action: "revoke", Requester: "alice", FromState: "issued", ToState: "revoked",
		TargetVersion: 7, Reason: "compromised workload", EvidenceRefs: []string{"audit:event-7"},
		RequiredApprovals: 2, CreatedAt: operationApprovalBaseTime,
		ExpiresAt: operationApprovalBaseTime.Add(time.Hour),
	}
}

func applyOperationApprovalRequest(ctx context.Context, s *store.Store, request store.OperationApprovalRequest) error {
	return s.WithTenant(ctx, request.TenantID, func(tx pgx.Tx) error {
		return s.ApplyOperationApprovalRequestedTx(ctx, tx, request)
	})
}

func applyOperationApprovalDecision(ctx context.Context, s *store.Store, decision store.OperationApprovalDecision) error {
	return s.WithTenant(ctx, decision.TenantID, func(tx pgx.Tx) error {
		return s.ApplyOperationApprovalDecisionTx(ctx, tx, decision)
	})
}

func operationApprovalDecision(request store.OperationApprovalRequest, approver, eventID string) store.OperationApprovalDecision {
	return store.OperationApprovalDecision{
		TenantID: request.TenantID, RequestID: request.ID, IntentDigest: request.IntentDigest,
		Approver: approver, Decision: store.ApprovalDecisionApprove, EventID: eventID,
		DecidedAt:            operationApprovalBaseTime.Add(10 * time.Minute),
		ExpectedResourceKind: request.ResourceKind, ExpectedResourceID: request.ResourceID,
		ExpectedAction: request.Action,
	}
}

func operationApprovalUse(request store.OperationApprovalRequest) store.OperationApprovalUse {
	return store.OperationApprovalUse{
		RequestID: request.ID, IntentDigest: request.IntentDigest, Requester: request.Requester,
		ResourceKind: request.ResourceKind, ResourceID: request.ResourceID, Action: request.Action,
		FromState: request.FromState, ToState: request.ToState, TargetVersion: request.TargetVersion,
		RequiredApprovals: request.RequiredApprovals,
	}
}

func TestOperationApprovalAuthorityImmutableIDAndDigestAreTenantScoped(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	request := operationApprovalRequest("77000000-0000-4000-8000-000000000001", tenantA)

	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatalf("project request: %v", err)
	}
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatalf("replay identical request: %v", err)
	}

	conflict := request
	conflict.IntentDigest = "sha256:different-intent-under-same-id"
	if err := applyOperationApprovalRequest(ctx, s, conflict); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("same ID with changed digest = %v, want ErrIdempotencyConflict", err)
	}
	if _, err := s.GetOperationApproval(ctx, tenantB, request.ID); !errors.Is(err, store.ErrApprovalRequestNotFound) {
		t.Fatalf("tenant B read tenant A request = %v, want ErrApprovalRequestNotFound", err)
	}
	if rows, err := s.ListOperationApprovals(ctx, tenantB, "", 20); err != nil || len(rows) != 0 {
		t.Fatalf("tenant B list = (%d rows, %v), want empty", len(rows), err)
	}

	tenantBRequest := request
	tenantBRequest.TenantID = tenantB
	tenantBRequest.IntentDigest = "sha256:tenant-b-intent"
	if err := applyOperationApprovalRequest(ctx, s, tenantBRequest); err != nil {
		t.Fatalf("same request ID in tenant B: %v", err)
	}
	gotA, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || gotA.IntentDigest != request.IntentDigest {
		t.Fatalf("tenant A request after tenant B insert = (%+v, %v)", gotA, err)
	}
	gotB, err := s.GetOperationApproval(ctx, tenantB, request.ID)
	if err != nil || gotB.IntentDigest != tenantBRequest.IntentDigest {
		t.Fatalf("tenant B request = (%+v, %v)", gotB, err)
	}
}

func TestOperationApprovalAuthorityRejectsUnrepresentableTargetVersion(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	request := operationApprovalRequest("77000000-0000-4000-8000-000000000008", tenantA)
	request.TargetVersion = math.MaxUint64

	err := applyOperationApprovalRequest(ctx, s, request)
	if err == nil || !strings.Contains(err.Error(), "target version exceeds PostgreSQL bigint") {
		t.Fatalf("unrepresentable target version = %v, want stable bigint-bound error", err)
	}
	if _, getErr := s.GetOperationApproval(ctx, tenantA, request.ID); !errors.Is(getErr, store.ErrApprovalRequestNotFound) {
		t.Fatalf("unrepresentable request persisted = %v, want ErrApprovalRequestNotFound", getErr)
	}
}

func TestOperationApprovalAuthorityDecisionReplayAndQuorumAreExact(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	request := operationApprovalRequest("77000000-0000-4000-8000-000000000002", tenantA)
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatal(err)
	}

	self := operationApprovalDecision(request, request.Requester, "77000000-0000-4000-8000-000000000101")
	if err := applyOperationApprovalDecision(ctx, s, self); !errors.Is(err, store.ErrApprovalSelfDecision) {
		t.Fatalf("self decision = %v, want ErrApprovalSelfDecision", err)
	}
	wrongDigest := operationApprovalDecision(request, "bob", "77000000-0000-4000-8000-000000000102")
	wrongDigest.IntentDigest = "sha256:not-the-reviewed-intent"
	if err := applyOperationApprovalDecision(ctx, s, wrongDigest); !errors.Is(err, store.ErrApprovalDigestMismatch) {
		t.Fatalf("wrong digest decision = %v, want ErrApprovalDigestMismatch", err)
	}

	first := operationApprovalDecision(request, "bob", "77000000-0000-4000-8000-000000000103")
	if err := applyOperationApprovalDecision(ctx, s, first); err != nil {
		t.Fatalf("first approval: %v", err)
	}
	if err := applyOperationApprovalDecision(ctx, s, first); err != nil {
		t.Fatalf("exact decision replay: %v", err)
	}
	got, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || got.ApprovalCount != 1 || got.Status != store.ApprovalStatusPending {
		t.Fatalf("after exact replay = (%+v, %v), want one approval and pending", got, err)
	}

	changedReplay := first
	changedReplay.EventID = "77000000-0000-4000-8000-000000000104"
	if err := applyOperationApprovalDecision(ctx, s, changedReplay); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("same principal decision with changed event = %v, want ErrIdempotencyConflict", err)
	}
	second := operationApprovalDecision(request, "carol", "77000000-0000-4000-8000-000000000105")
	if err := applyOperationApprovalDecision(ctx, s, second); err != nil {
		t.Fatalf("second distinct approval: %v", err)
	}
	got, err = s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || got.ApprovalCount != 2 || got.Status != store.ApprovalStatusApproved {
		t.Fatalf("quorum state = (%+v, %v), want two approvals and approved", got, err)
	}
}

func TestOperationApprovalAuthorityDecisionReplayUsesPostgresTimestampPrecisionAUD68(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	request := operationApprovalRequest("77000000-0000-4000-8000-000000000009", tenantA)
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatal(err)
	}

	decision := operationApprovalDecision(request, "bob", "77000000-0000-4000-8000-000000000131")
	decision.DecidedAt = operationApprovalBaseTime.Add(10*time.Minute + 731*time.Nanosecond)
	if err := applyOperationApprovalDecision(ctx, s, decision); err != nil {
		t.Fatalf("first sub-microsecond decision: %v", err)
	}
	if err := applyOperationApprovalDecision(ctx, s, decision); err != nil {
		t.Fatalf("exact retained-event replay after PostgreSQL timestamp coercion: %v", err)
	}

	changed := decision
	changed.DecidedAt = decision.DecidedAt.Add(2 * time.Microsecond)
	if err := applyOperationApprovalDecision(ctx, s, changed); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("decision replay with changed database-representable time = %v, want ErrIdempotencyConflict", err)
	}
}

func TestOperationApprovalAuthorityPrincipalCannotReverseTheirDecision(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	request := operationApprovalRequest("77000000-0000-4000-8000-000000000003", tenantA)
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatal(err)
	}
	approve := operationApprovalDecision(request, "bob", "77000000-0000-4000-8000-000000000111")
	if err := applyOperationApprovalDecision(ctx, s, approve); err != nil {
		t.Fatalf("approve: %v", err)
	}
	opposite := approve
	opposite.Decision = store.ApprovalDecisionDeny
	opposite.EventID = "77000000-0000-4000-8000-000000000112"
	if err := applyOperationApprovalDecision(ctx, s, opposite); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("same principal opposite decision = %v, want ErrIdempotencyConflict", err)
	}
	got, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || got.Status != store.ApprovalStatusPending || got.ApprovalCount != 1 {
		t.Fatalf("opposite decision mutated request = (%+v, %v), want pending with one approval", got, err)
	}
}

func TestOperationApprovalAuthorityExpiryAndSupersessionFailClosed(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()

	expired := operationApprovalRequest("77000000-0000-4000-8000-000000000004", tenantA)
	if err := applyOperationApprovalRequest(ctx, s, expired); err != nil {
		t.Fatal(err)
	}
	late := operationApprovalDecision(expired, "bob", "77000000-0000-4000-8000-000000000121")
	late.DecidedAt = expired.ExpiresAt
	if err := applyOperationApprovalDecision(ctx, s, late); !errors.Is(err, store.ErrApprovalExpired) {
		t.Fatalf("decision at expiry = %v, want ErrApprovalExpired", err)
	}

	superseded := operationApprovalRequest("77000000-0000-4000-8000-000000000005", tenantA)
	if err := applyOperationApprovalRequest(ctx, s, superseded); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyOperationApprovalStatusTx(ctx, tx, tenantA, superseded.ID,
			superseded.IntentDigest, store.ApprovalStatusSuperseded, operationApprovalBaseTime.Add(5*time.Minute))
	}); err != nil {
		t.Fatalf("supersede: %v", err)
	}
	decision := operationApprovalDecision(superseded, "bob", "77000000-0000-4000-8000-000000000122")
	if err := applyOperationApprovalDecision(ctx, s, decision); !errors.Is(err, store.ErrApprovalSuperseded) {
		t.Fatalf("decision on superseded request = %v, want ErrApprovalSuperseded", err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := s.ValidateOperationApprovalUseTx(ctx, tx, tenantA,
			operationApprovalUse(superseded), operationApprovalBaseTime.Add(10*time.Minute))
		return err
	}); !errors.Is(err, store.ErrApprovalSuperseded) {
		t.Fatalf("use superseded request = %v, want ErrApprovalSuperseded", err)
	}
}

func TestOperationApprovalAuthorityUseValidationAndConsumptionAreExact(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	request := operationApprovalRequest("77000000-0000-4000-8000-000000000006", tenantA)
	request.RequiredApprovals = 1
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatal(err)
	}
	if err := applyOperationApprovalDecision(ctx, s,
		operationApprovalDecision(request, "bob", "77000000-0000-4000-8000-000000000131")); err != nil {
		t.Fatalf("approve: %v", err)
	}

	use := operationApprovalUse(request)
	exactUse, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		t.Fatalf("build exact approval use: %v", err)
	}
	emptyEvidence := exactUse
	emptyEvidence.Reason = ""
	emptyEvidence.EvidenceRefs = []string{}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := s.ValidateOperationApprovalUseTx(ctx, tx, tenantA, emptyEvidence,
			operationApprovalBaseTime.Add(20*time.Minute))
		return err
	}); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("fresh command with cleared reason/evidence = %v, want ErrApprovalDrifted", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*store.OperationApprovalUse)
		want   error
	}{
		{"digest", func(u *store.OperationApprovalUse) { u.IntentDigest = "sha256:other" }, store.ErrApprovalDigestMismatch},
		{"requester", func(u *store.OperationApprovalUse) { u.Requester = "mallory" }, store.ErrApprovalDrifted},
		{"resource", func(u *store.OperationApprovalUse) { u.ResourceID = "identity/other" }, store.ErrApprovalDrifted},
		{"action", func(u *store.OperationApprovalUse) { u.Action = "rotate" }, store.ErrApprovalDrifted},
		{"from-state", func(u *store.OperationApprovalUse) { u.FromState = "deployed" }, store.ErrApprovalDrifted},
		{"to-state", func(u *store.OperationApprovalUse) { u.ToState = "retired" }, store.ErrApprovalDrifted},
		{"target-version", func(u *store.OperationApprovalUse) { u.TargetVersion++ }, store.ErrApprovalDrifted},
		{"quorum", func(u *store.OperationApprovalUse) { u.RequiredApprovals++ }, store.ErrApprovalDrifted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			drifted := use
			tc.mutate(&drifted)
			err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				_, err := s.ValidateOperationApprovalUseTx(ctx, tx, tenantA, drifted,
					operationApprovalBaseTime.Add(20*time.Minute))
				return err
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("drift validation = %v, want %v", err, tc.want)
			}
		})
	}

	const eventID = "77000000-0000-4000-8000-000000000132"
	consume := func(use store.OperationApprovalUse, event string) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if _, err := s.ValidateOperationApprovalUseTx(ctx, tx, tenantA, use,
				operationApprovalBaseTime.Add(20*time.Minute)); err != nil {
				return err
			}
			return s.ConsumeOperationApprovalTx(ctx, tx, tenantA, use, event,
				operationApprovalBaseTime.Add(20*time.Minute))
		})
	}
	if err := consume(use, eventID); err != nil {
		t.Fatalf("first exact consume: %v", err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ConsumeOperationApprovalTx(ctx, tx, tenantA, use, eventID,
			operationApprovalBaseTime.Add(20*time.Minute))
	}); err != nil {
		t.Fatalf("same target-event replay: %v", err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ConsumeOperationApprovalTx(ctx, tx, tenantA, use,
			"77000000-0000-4000-8000-000000000133", operationApprovalBaseTime.Add(20*time.Minute))
	}); !errors.Is(err, store.ErrApprovalConsumed) {
		t.Fatalf("second target event consume = %v, want ErrApprovalConsumed", err)
	}
	got, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || got.Status != store.ApprovalStatusConsumed || got.ConsumedEventID != eventID {
		t.Fatalf("consumed authority = (%+v, %v)", got, err)
	}
}

func TestOperationApprovalAuthorityBindsProfileRevisionAndIssuanceTTL(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	binding := store.OperationApprovalIssuanceBinding{
		ProfileName: "prod", ProfileID: "88000000-0000-4000-8000-000000000001",
		ProfileVersion: 7, ProfileSpecDigest: "sha256:" + strings.Repeat("a", 64),
		RequestedTTLSeconds: 86400, EffectiveTTLSeconds: 43200,
	}
	evidence, err := binding.EvidenceRefs()
	if err != nil {
		t.Fatalf("issuance evidence: %v", err)
	}
	request := operationApprovalRequest("77000000-0000-4000-8000-000000000009", tenantA)
	request.Action = "issue"
	request.FromState = "requested"
	request.ToState = "issued"
	request.RequiredApprovals = 1
	request.EvidenceRefs = append([]string{"idempotency-key-sha256:exact"}, evidence...)
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatal(err)
	}
	if err := applyOperationApprovalDecision(ctx, s,
		operationApprovalDecision(request, "bob", "77000000-0000-4000-8000-000000000151")); err != nil {
		t.Fatalf("approve: %v", err)
	}
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		t.Fatalf("reconstruct use: %v", err)
	}
	if use.Issuance == nil || *use.Issuance != binding {
		t.Fatalf("reconstructed issuance = %+v, want %+v", use.Issuance, binding)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*store.OperationApprovalUse)
	}{
		{"omitted", func(u *store.OperationApprovalUse) { u.Issuance = nil }},
		{"profile-id", func(u *store.OperationApprovalUse) { u.Issuance.ProfileID = "88000000-0000-4000-8000-000000000002" }},
		{"profile-version", func(u *store.OperationApprovalUse) { u.Issuance.ProfileVersion++ }},
		{"profile-spec", func(u *store.OperationApprovalUse) {
			u.Issuance.ProfileSpecDigest = "sha256:" + strings.Repeat("b", 64)
		}},
		{"requested-ttl", func(u *store.OperationApprovalUse) { u.Issuance.RequestedTTLSeconds++ }},
		{"effective-ttl", func(u *store.OperationApprovalUse) { u.Issuance.EffectiveTTLSeconds-- }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			drifted := use
			if use.Issuance != nil {
				copyBinding := *use.Issuance
				drifted.Issuance = &copyBinding
			}
			tc.mutate(&drifted)
			err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				_, validateErr := s.ValidateOperationApprovalUseTx(ctx, tx, tenantA, drifted,
					operationApprovalBaseTime.Add(20*time.Minute))
				return validateErr
			})
			if !errors.Is(err, store.ErrApprovalDrifted) {
				t.Fatalf("drift validation = %v, want ErrApprovalDrifted", err)
			}
		})
	}
}

func TestOperationApprovalIssuanceBindingRejectsNamedProfileWithoutExactRevision(t *testing.T) {
	namedWithoutRevision := store.OperationApprovalIssuanceBinding{
		ProfileName: "prod", RequestedTTLSeconds: 86400, EffectiveTTLSeconds: 43200,
	}
	if _, err := namedWithoutRevision.EvidenceRefs(); err == nil {
		t.Fatal("named profile without id/version/spec digest was accepted")
	}

	defaultProfile := store.OperationApprovalIssuanceBinding{
		RequestedTTLSeconds: 86400, EffectiveTTLSeconds: 43200,
	}
	refs, err := defaultProfile.EvidenceRefs()
	if err != nil {
		t.Fatalf("empty-profile TTL binding: %v", err)
	}
	request := operationApprovalRequest("77000000-0000-4000-8000-000000000010", tenantA)
	request.Action = "issue"
	request.FromState = "requested"
	request.ToState = "issued"
	request.EvidenceRefs = refs
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		t.Fatalf("reconstruct empty-profile TTL binding: %v", err)
	}
	if use.Issuance == nil || *use.Issuance != defaultProfile {
		t.Fatalf("empty-profile issuance = %+v, want %+v", use.Issuance, defaultProfile)
	}
}

func TestOperationApprovalAuthorityConsumedReplayStillValidatesExactUse(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	request := operationApprovalRequest("77000000-0000-4000-8000-000000000007", tenantA)
	request.RequiredApprovals = 1
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatal(err)
	}
	decision := operationApprovalDecision(request, "bob", "77000000-0000-4000-8000-000000000141")
	if err := applyOperationApprovalDecision(ctx, s, decision); err != nil {
		t.Fatal(err)
	}
	use := operationApprovalUse(request)
	const eventID = "77000000-0000-4000-8000-000000000142"
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ConsumeOperationApprovalTx(ctx, tx, tenantA, use, eventID,
			operationApprovalBaseTime.Add(20*time.Minute))
	}); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	beforeRequestReplay, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil {
		t.Fatalf("load consumed request before request-event replay: %v", err)
	}
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatalf("replay original request event after consume: %v", err)
	}
	afterRequestReplay, err := s.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil || afterRequestReplay.Status != store.ApprovalStatusConsumed ||
		afterRequestReplay.ConsumedEventID != eventID || afterRequestReplay.ConsumedAt == nil ||
		!afterRequestReplay.UpdatedAt.Equal(beforeRequestReplay.UpdatedAt) {
		t.Fatalf("request-event replay rewound terminal metadata: before=%+v after=%+v err=%v",
			beforeRequestReplay, afterRequestReplay, err)
	}
	if err := applyOperationApprovalDecision(ctx, s, decision); err != nil {
		t.Fatalf("exact decision projection replay after consume: %v", err)
	}

	driftedReplay := use
	driftedReplay.TargetVersion++
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ConsumeOperationApprovalTx(ctx, tx, tenantA, driftedReplay, eventID,
			operationApprovalBaseTime.Add(20*time.Minute))
	}); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("same event ID with drifted use = %v, want ErrApprovalDrifted", err)
	}
}

func TestConsumedOperationApprovalRecoveryIgnoresMutableProfileEvidenceAndBindsCSR(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	request := operationApprovalRequest("77000000-0000-4000-8000-000000000009", tenantA)
	request.RequiredApprovals = 1
	request.ResourceName = "name-at-approval"
	request.EvidenceRefs = []string{
		"idempotency-key-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"profile:profile-at-approval",
		"csr-sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatal(err)
	}
	if err := applyOperationApprovalDecision(ctx, s,
		operationApprovalDecision(request, "bob", "77000000-0000-4000-8000-000000000151")); err != nil {
		t.Fatal(err)
	}
	const eventID = "77000000-0000-4000-8000-000000000152"
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ConsumeOperationApprovalTx(ctx, tx, tenantA, operationApprovalUse(request), eventID,
			operationApprovalBaseTime.Add(20*time.Minute))
	}); err != nil {
		t.Fatalf("consume exact authority: %v", err)
	}

	attempt := store.OperationApprovalAttempt{
		ResourceKind: request.ResourceKind, ResourceID: request.ResourceID,
		Action: request.Action, Requester: request.Requester, ToState: request.ToState,
		Reason:               request.Reason,
		IdempotencyKeyDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SubjectCSRDigest:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	got, found, err := s.ConsumedOperationApprovalForAttempt(ctx, tenantA, attempt)
	if err != nil || !found || got.ID != request.ID || got.ConsumedEventID != eventID {
		t.Fatalf("recover after profile/name drift = (%+v, found=%v, err=%v)", got, found, err)
	}
	if len(got.EvidenceRefs) != 3 || !strings.Contains(strings.Join(got.EvidenceRefs, "\n"), "profile:profile-at-approval") {
		t.Fatalf("recovered request rewrote original profile evidence: %v", got.EvidenceRefs)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*store.OperationApprovalAttempt)
	}{
		{"different idempotency key", func(a *store.OperationApprovalAttempt) { a.IdempotencyKeyDigest = strings.Repeat("c", 64) }},
		{"different CSR", func(a *store.OperationApprovalAttempt) { a.SubjectCSRDigest = strings.Repeat("d", 64) }},
		{"missing CSR", func(a *store.OperationApprovalAttempt) { a.SubjectCSRDigest = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mismatch := attempt
			tc.mutate(&mismatch)
			if got, found, err := s.ConsumedOperationApprovalForAttempt(ctx, tenantA, mismatch); err != nil || found {
				t.Fatalf("mismatched recovery = (%+v, found=%v, err=%v), want no match", got, found, err)
			}
		})
	}
}
