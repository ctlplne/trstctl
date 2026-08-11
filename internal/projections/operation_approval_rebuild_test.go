// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func resetOperationApprovalProjectionTables(t *testing.T, s *store.Store) {
	t.Helper()
	reset := func() {
		t.Helper()
		if _, err := s.SystemPool().Exec(context.Background(),
			`TRUNCATE operation_approval_decisions, operation_approval_requests`); err != nil {
			t.Fatalf("truncate operation approval projections: %v", err)
		}
	}
	reset()
	t.Cleanup(reset)
}

func operationApprovalJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal operation approval event: %v", err)
	}
	return raw
}

func TestOperationApprovalProjectionReplayAndRebuildDeriveExactState(t *testing.T) {
	s := newStore(t)
	resetOperationApprovalProjectionTables(t, s)
	log := openLog(t)
	ctx := context.Background()
	projector := projections.New(s)
	createdAt := time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC)
	const (
		requestID = "77100000-0000-4000-8000-000000000001"
		digest    = "sha256:projection-exact-intent"
	)

	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegistered("approval-rebuild"),
	}); err != nil {
		t.Fatalf("append tenant: %v", err)
	}
	if _, err := log.Append(ctx, events.Event{
		ID: requestID, Type: projections.EventApprovalRequested, TenantID: tenantA,
		Data: operationApprovalJSON(t, projections.ApprovalRequested{
			ID: requestID, IntentDigest: digest, ResourceKind: "identity",
			ResourceID: "identity/rebuild", ResourceName: "rebuild",
			Action: "revoke", Requester: "alice", FromState: "issued", ToState: "revoked",
			TargetVersion: 4, Reason: "rebuild exactness", EvidenceRefs: []string{"audit:4"},
			RequiredApprovals: 2, CreatedAt: createdAt, ExpiresAt: createdAt.Add(time.Hour),
		}),
	}); err != nil {
		t.Fatalf("append request: %v", err)
	}
	first, err := log.Append(ctx, events.Event{
		ID:   "77100000-0000-4000-8000-000000000101",
		Type: projections.EventApprovalDecisionRecorded, TenantID: tenantA,
		Data: operationApprovalJSON(t, projections.ApprovalDecisionRecorded{
			RequestID: requestID, IntentDigest: digest, Approver: "bob",
			Decision: store.ApprovalDecisionApprove, DecidedAt: createdAt.Add(5 * time.Minute),
			ExpectedResourceKind: "identity", ExpectedResourceID: "identity/rebuild",
			ExpectedAction: "revoke",
		}),
	})
	if err != nil {
		t.Fatalf("append first decision: %v", err)
	}
	secondAt := createdAt.Add(6 * time.Minute)
	if _, err := log.Append(ctx, events.Event{
		ID:   "77100000-0000-4000-8000-000000000102",
		Type: projections.EventApprovalDecisionRecorded, TenantID: tenantA,
		Data: operationApprovalJSON(t, projections.ApprovalDecisionRecorded{
			RequestID: requestID, IntentDigest: digest, Approver: "carol",
			Decision: store.ApprovalDecisionApprove, DecidedAt: secondAt,
			ExpectedResourceKind: "identity", ExpectedResourceID: "identity/rebuild",
			ExpectedAction: "revoke",
		}),
	}); err != nil {
		t.Fatalf("append second decision: %v", err)
	}

	if err := projector.Project(ctx, log); err != nil {
		t.Fatalf("project operation approval history: %v", err)
	}
	if err := projector.Apply(ctx, first); err != nil {
		t.Fatalf("exact decision event replay: %v", err)
	}
	warm, err := s.GetOperationApproval(ctx, tenantA, requestID)
	if err != nil || warm.Status != store.ApprovalStatusApproved || warm.ApprovalCount != 2 {
		t.Fatalf("warm approval = (%+v, %v), want approved 2-of-2", warm, err)
	}

	// A read-model row with no source event must disappear on rebuild. This is the
	// practical classification check: merely making event handlers idempotent is
	// insufficient if RebuildReadModelTx never truncates the new tables.
	phantom := store.OperationApprovalRequest{
		ID: "77100000-0000-4000-8000-000000000099", TenantID: tenantA,
		IntentDigest: "sha256:no-source-event", ResourceKind: "identity",
		ResourceID: "identity/phantom", Action: "revoke", Requester: "mallory",
		FromState: "issued", ToState: "revoked", TargetVersion: 9,
		RequiredApprovals: 1, CreatedAt: createdAt, ExpiresAt: createdAt.Add(time.Hour),
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyOperationApprovalRequestedTx(ctx, tx, phantom)
	}); err != nil {
		t.Fatalf("seed phantom read-model row: %v", err)
	}

	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild operation approval history: %v", err)
	}
	rebuilt, err := s.GetOperationApproval(ctx, tenantA, requestID)
	if err != nil {
		t.Fatalf("get rebuilt request: %v", err)
	}
	if rebuilt.Status != warm.Status || rebuilt.ApprovalCount != warm.ApprovalCount {
		t.Errorf("rebuild state = %s %d, warm = %s %d",
			rebuilt.Status, rebuilt.ApprovalCount, warm.Status, warm.ApprovalCount)
	}
	if !rebuilt.UpdatedAt.Equal(secondAt) {
		t.Errorf("rebuilt updated_at = %s, want last decision time %s", rebuilt.UpdatedAt, secondAt)
	}
	if _, err := s.GetOperationApproval(ctx, tenantA, phantom.ID); !errors.Is(err, store.ErrApprovalRequestNotFound) {
		t.Errorf("phantom row survived rebuild: %v, want ErrApprovalRequestNotFound", err)
	}
}
