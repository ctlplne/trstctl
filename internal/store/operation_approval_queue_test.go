// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func TestOperationApprovalQueueIsEmptyBeforeTenantProjectionMaterializes(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	const blankTenant = "77000000-0000-4000-8000-000000000099"

	rows, err := s.ListOperationApprovalsPage(ctx, blankTenant, store.OperationApprovalListOptions{
		Status: store.ApprovalStatusPending, Limit: 20, Visibility: store.AllOperationApprovalDomains(),
	})
	if err != nil {
		t.Fatalf("list blank tenant approval queue: %v", err)
	}
	if rows == nil || len(rows) != 0 {
		t.Fatalf("blank tenant approval queue = %#v, want a non-nil empty page", rows)
	}
}

func TestOperationApprovalQueueStatusFilterUsesEffectiveExpiry(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	request := operationApprovalRequest("77000000-0000-4000-8000-000000000201", tenantA)
	request.RequiredApprovals = 1
	request.CreatedAt = now.Add(-2 * time.Hour)
	request.ExpiresAt = now.Add(-time.Hour)
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatal(err)
	}
	decision := operationApprovalDecision(request, "bob", "77000000-0000-4000-8000-000000000202")
	decision.DecidedAt = request.CreatedAt.Add(10 * time.Minute)
	if err := applyOperationApprovalDecision(ctx, s, decision); err != nil {
		t.Fatal(err)
	}

	approved, err := s.ListOperationApprovalsPage(ctx, tenantA, store.OperationApprovalListOptions{
		Status: store.ApprovalStatusApproved, Limit: 20, Visibility: store.AllOperationApprovalDomains(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(approved) != 0 {
		t.Fatalf("approved queue returned %d expired request(s), want none: %+v", len(approved), approved)
	}

	expired, err := s.ListOperationApprovalsPage(ctx, tenantA, store.OperationApprovalListOptions{
		Status: store.ApprovalStatusExpired, Limit: 20, Visibility: store.AllOperationApprovalDomains(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0].ID != request.ID || expired[0].Status != store.ApprovalStatusExpired {
		t.Fatalf("expired queue = %+v, want effective expired request %s", expired, request.ID)
	}
}

func TestOperationApprovalQueueStatusAndFilterUseOneDatabaseSnapshot(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	request := operationApprovalRequest("77000000-0000-4000-8000-000000000203", tenantA)
	request.CreatedAt = now.Add(-time.Hour)
	// Race-enabled full-suite runs can leave this goroutine unscheduled for more
	// than two seconds on constrained CI hosts. Give the transaction enough time
	// to start before expiry; the test still waits past the exact deadline below.
	request.ExpiresAt = now.Add(10 * time.Second)
	if err := applyOperationApprovalRequest(ctx, s, request); err != nil {
		t.Fatal(err)
	}

	// Hold the table after ListOperationApprovalsPage starts its transaction. In
	// PostgreSQL, now() is the transaction-start instant, so the SQL pending
	// predicate sees this request as live even though the wall clock crosses its
	// expiry while the SELECT waits. The returned status must use that same
	// database snapshot; mixing in a later Go clock would return an "expired" row
	// from a status=pending page.
	blocker, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(ctx) }()
	if _, err := blocker.Exec(ctx, `LOCK TABLE operation_approval_requests IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}

	type result struct {
		rows []store.OperationApprovalRequest
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		rows, err := s.ListOperationApprovalsPage(ctx, tenantA, store.OperationApprovalListOptions{
			Status: store.ApprovalStatusPending, Limit: 20, Visibility: store.AllOperationApprovalDomains(),
		})
		resultCh <- result{rows: rows, err: err}
	}()

	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case early := <-resultCh:
			if early.err != nil {
				t.Fatalf("approval queue SELECT failed before reaching the lock: %v", early.err)
			}
			t.Fatalf("approval queue SELECT returned before reaching the held table lock: %+v", early.rows)
		default:
		}
		var waiting int
		// Observe the relation lock directly instead of matching pg_stat_activity's
		// driver- and server-version-dependent query text. Use the blocker
		// transaction's own connection so a small system pool cannot starve this
		// observation while the blocker holds its slot.
		if err := blocker.QueryRow(ctx, `
			SELECT count(*)
			  FROM pg_locks l
			  JOIN pg_class c ON c.oid = l.relation
			 WHERE c.relname = 'operation_approval_requests'
			   AND l.mode = 'AccessShareLock'
			   AND NOT l.granted`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("approval queue SELECT did not reach the table lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if wait := time.Until(request.ExpiresAt.Add(100 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	got := <-resultCh
	if got.err != nil {
		t.Fatal(got.err)
	}
	if len(got.rows) != 1 || got.rows[0].ID != request.ID || got.rows[0].Status != store.ApprovalStatusPending {
		t.Fatalf("pending snapshot page = %+v, want request %s consistently pending", got.rows, request.ID)
	}
}

func TestOperationApprovalQueuePaginatesNewestFirstWithoutHidingAuthorizedDomains(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	requests := []store.OperationApprovalRequest{
		operationApprovalRequest("77000000-0000-4000-8000-000000000211", tenantA),
		operationApprovalRequest("77000000-0000-4000-8000-000000000212", tenantA),
		operationApprovalRequest("77000000-0000-4000-8000-000000000213", tenantA),
		operationApprovalRequest("77000000-0000-4000-8000-000000000214", tenantA),
	}
	requests[0].ResourceKind, requests[0].Action = "identity", "issue"
	requests[1].ResourceKind, requests[1].Action = "secret", "rotate"
	requests[2].ResourceKind, requests[2].Action = "managed_key", "managedkey:zeroize"
	requests[3].ResourceKind, requests[3].Action = "identity", "revoke"
	for i := range requests {
		requests[i].IntentDigest = "sha256:queue-" + requests[i].ID
		requests[i].CreatedAt = now.Add(time.Duration(i) * time.Minute)
		requests[i].ExpiresAt = now.Add(2 * time.Hour)
		if err := applyOperationApprovalRequest(ctx, s, requests[i]); err != nil {
			t.Fatal(err)
		}
	}

	visibility := store.OperationApprovalDomainVisibility{CertificateOperations: true}
	first, err := s.ListOperationApprovalsPage(ctx, tenantA, store.OperationApprovalListOptions{
		Status: store.ApprovalStatusPending, Limit: 1, Visibility: visibility,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].ID != requests[3].ID {
		t.Fatalf("first certificate-only page = %+v, want newest identity %s", first, requests[3].ID)
	}
	second, err := s.ListOperationApprovalsPage(ctx, tenantA, store.OperationApprovalListOptions{
		Status: store.ApprovalStatusPending, Limit: 1, Visibility: visibility,
		AfterCreatedAt: &first[0].CreatedAt, AfterID: first[0].ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0].ID != requests[0].ID {
		t.Fatalf("second certificate-only page = %+v, want older identity %s", second, requests[0].ID)
	}
	third, err := s.ListOperationApprovalsPage(ctx, tenantA, store.OperationApprovalListOptions{
		Status: store.ApprovalStatusPending, Limit: 1, Visibility: visibility,
		AfterCreatedAt: &second[0].CreatedAt, AfterID: second[0].ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(third) != 0 {
		t.Fatalf("third certificate-only page = %+v, want end of queue", third)
	}
}
