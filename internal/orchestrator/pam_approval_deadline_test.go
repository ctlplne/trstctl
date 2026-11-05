// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A recovered rule evaluation already has a deadline. Creating its review
// later must not restart that clock or let a retry enlarge its authority.
func TestOperationApprovalCannotOutliveItsFrozenDeadlineA261(t *testing.T) {
	s := newStore(t)
	resetOrchestratorOperationApprovals(t, s)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "frozen-review-deadline"}); err != nil {
		t.Fatal(err)
	}
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, s, nil)
	deadline := time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
	intent := orchestrator.OperationApprovalIntent{ResourceKind: "pam", ResourceID: "pam:deadline-proof", ResourceName: "postgres/orders", Action: "activate", Requester: "deadline-requester", FromState: "attested", ToState: "active", Reason: "INC-261", EvidenceRefs: []string{"pam-auto-evaluation:fixed-public-id"}, RequiredApprovals: 1, TTL: time.Hour, ExpiresAtNotAfter: deadline}
	review, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, intent)
	if err != nil {
		t.Fatal(err)
	}
	if !review.ExpiresAt.Equal(deadline) {
		t.Fatalf("review expires %s, frozen deadline %s", review.ExpiresAt, deadline)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, intent)
	if err != nil || replay.ID != review.ID || replay.IntentDigest != review.IntentDigest || !replay.ExpiresAt.Equal(deadline) {
		t.Fatalf("replay moved the deadline: %+v, %v", replay, err)
	}
	after, err := log.LastSequence(ctx)
	if err != nil || after != head {
		t.Fatalf("replay appended events: %d -> %d, %v", head, after, err)
	}
	expired := intent
	expired.ResourceID = "pam:expired-deadline-proof"
	expired.ExpiresAtNotAfter = time.Now().UTC().Add(-time.Minute)
	if _, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, expired); !errors.Is(err, store.ErrApprovalExpired) {
		t.Fatalf("past deadline = %v, want ErrApprovalExpired", err)
	}
	after, err = log.LastSequence(ctx)
	if err != nil || after != head {
		t.Fatalf("expired request changed the source: %d -> %d, %v", head, after, err)
	}
	shorter := intent
	shorter.ResourceID = "pam:shorter-deadline-proof"
	shorter.TTL = 10 * time.Second
	short, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, shorter)
	if err != nil || short.ExpiresAt.Sub(short.CreatedAt) != shorter.TTL || short.ExpiresAt.After(deadline) {
		t.Fatalf("shorter review = %+v, %v", short, err)
	}
	if err := projections.New(s).Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := s.GetOperationApproval(ctx, tenantA, review.ID)
	if err != nil || !rebuilt.ExpiresAt.Equal(deadline) || rebuilt.IntentDigest != review.IntentDigest {
		t.Fatalf("rebuilt deadline differs: %+v, %v", rebuilt, err)
	}
}
