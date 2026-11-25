// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

// EXC-WIRE-03 — store tests for the served dual-control approval tables, the
// distinct-approver / self-approval-rejection backbone of the served issuance gate
// (SEC-002, the served half of RED-004). They run against the embedded PostgreSQL +
// FORCE-d RLS the package stands up (offboard_test.go's TestMain), so a lost tenant
// clause or a broken self-approval check is caught here. They reuse the shared
// newStore/tenantA/tenantB/seedTwoTenants harness.

// TestIssuanceApprovalDistinctAndSelfApproval pins the core dual-control invariants:
//   - a request requires `required` DISTINCT approvers;
//   - the requester may NOT approve their own request (self-approval rejected);
//   - the requester's own approval, even if somehow present, is never counted toward
//     the distinct threshold;
//   - re-approving by the same approver is idempotent (no double-count).
func TestIssuanceApprovalDistinctAndSelfApproval(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	const resource = "id-1"
	const action = "issue"
	// Open the request with bob as the requester, requiring 2 distinct approvals.
	if err := s.OpenIssuanceApprovalRequest(ctx, tenantA, resource, action, "bob", 2); err != nil {
		t.Fatalf("OpenIssuanceApprovalRequest: %v", err)
	}

	// (1) Self-approval is refused and never recorded.
	if _, err := s.ApproveIssuance(ctx, tenantA, resource, action, "bob"); !errors.Is(err, store.ErrSelfIssuanceApproval) {
		t.Fatalf("self-approval = %v, want ErrSelfIssuanceApproval (the requester cannot approve their own request)", err)
	}

	// (2) Not yet approved by enough distinct approvers.
	if ok, err := s.HasDistinctApproval(ctx, tenantA, resource, action, "bob", 2); err != nil || ok {
		t.Fatalf("HasDistinctApproval before approvals = (%v, %v), want (false, nil)", ok, err)
	}

	// (3) One distinct approver — still short of the 2 required.
	if n, err := s.ApproveIssuance(ctx, tenantA, resource, action, "carol"); err != nil || n != 1 {
		t.Fatalf("first approval = (%d, %v), want (1, nil)", n, err)
	}
	if ok, _ := s.HasDistinctApproval(ctx, tenantA, resource, action, "bob", 2); ok {
		t.Fatal("one distinct approver must not satisfy a 2-of-N requirement")
	}

	// Idempotent: carol re-approving does not bump the distinct count.
	if n, err := s.ApproveIssuance(ctx, tenantA, resource, action, "carol"); err != nil || n != 1 {
		t.Fatalf("idempotent re-approval = (%d, %v), want (1, nil)", n, err)
	}

	// (4) A second DISTINCT approver satisfies dual control.
	if n, err := s.ApproveIssuance(ctx, tenantA, resource, action, "dave"); err != nil || n != 2 {
		t.Fatalf("second distinct approval = (%d, %v), want (2, nil)", n, err)
	}
	if ok, err := s.HasDistinctApproval(ctx, tenantA, resource, action, "bob", 2); err != nil || !ok {
		t.Fatalf("HasDistinctApproval with 2 distinct approvers = (%v, %v), want (true, nil)", ok, err)
	}

	// Anonymous approver is refused.
	if _, err := s.ApproveIssuance(ctx, tenantA, resource, action, ""); !errors.Is(err, store.ErrAnonymousIssuanceApproval) {
		t.Fatalf("anonymous approval = %v, want ErrAnonymousIssuanceApproval", err)
	}
}

func TestIssuanceApprovalRejectsHistoricalDelegatedMinter(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)
	if _, err := s.CreateAPIToken(ctx, store.APITokenRecord{TenantID: tenantA, TokenHash: privacy.SubjectRef(tenantA, "cr972-issuance-holder"), Subject: "cr972-service", MintedBy: "cr972-minter"}); err != nil {
		t.Fatal(err)
	}
	if err := s.OpenIssuanceApprovalRequest(ctx, tenantA, "cr972-identity", "issue", "cr972-service", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveIssuance(ctx, tenantA, "cr972-identity", "issue", "cr972-minter"); !errors.Is(err, store.ErrSelfIssuanceApproval) {
		t.Fatalf("token minter approved delegated identity request: %v", err)
	}
	if count, err := s.ApproveIssuance(ctx, tenantA, "cr972-identity", "issue", "independent"); err != nil || count != 1 {
		t.Fatalf("independent decision = (%d, %v), want one approval", count, err)
	}
}

func TestHistoricalDelegatedMinterApprovalCannotSatisfyIssuanceQuorum(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)
	const resource, action = "cr972-old-identity", "issue"
	const requester, minter = "cr972-old-service", "cr972-old-minter"
	if _, err := s.CreateAPIToken(ctx, store.APITokenRecord{TenantID: tenantA, TokenHash: privacy.SubjectRef(tenantA, "cr972-old-issuance-holder"), Subject: requester, MintedBy: minter}); err != nil {
		t.Fatal(err)
	}
	if err := s.OpenIssuanceApprovalRequest(ctx, tenantA, resource, action, requester, 1); err != nil {
		t.Fatal(err)
	}
	// A pre-fix approval event already projected this row. Preserve it as audit
	// history, but do not let it authorize a future issuance.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO issuance_approvals (tenant_id, resource, action, approver) VALUES ($1,$2,$3,$4)`,
			tenantA, resource, action, minter); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE issuance_approval_requests SET status='approved' WHERE tenant_id=$1 AND resource=$2 AND action=$3`, tenantA, resource, action)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := s.GetIssuanceApproval(ctx, tenantA, resource, action)
	if err != nil || approval.Approvals != 0 || approval.Status != "pending" {
		t.Errorf("retained minter approval counted in inventory: status=%s count=%d err=%v", approval.Status, approval.Approvals, err)
	}
	if ok, err := s.HasDistinctApproval(ctx, tenantA, resource, action, requester, 1); err != nil || ok {
		t.Errorf("retained minter approval satisfied the gate: ok=%t err=%v", ok, err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := s.ConsumeIssuanceApprovalTx(ctx, tx, tenantA, resource, action, requester, 1)
		return err
	}); !errors.Is(err, store.ErrIssuanceApprovalQuorumNotMet) {
		t.Errorf("retained minter approval was consumable: %v", err)
	}
	if count, err := s.ApproveIssuance(ctx, tenantA, resource, action, "independent"); err != nil || count != 1 {
		t.Errorf("one independent approval count=%d err=%v, want 1", count, err)
	}
}

// TestIssuanceApprovalRequesterNeverCounts proves the requester's own approval can
// never reach the threshold even if recorded before the requester is bound: the
// distinct count excludes the requester. This is the belt-and-suspenders behind the
// self-approval rejection (HasDistinctApproval filters approver <> requester).
func TestIssuanceApprovalRequesterNeverCounts(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	const resource, action = "id-2", "revoke"
	// Open WITHOUT a requester (as the approval endpoint would before the requester
	// attempts the gated transition), so an approval by "mallory" is recorded.
	if err := s.OpenIssuanceApprovalRequest(ctx, tenantA, resource, action, "", 1); err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := s.ApproveIssuance(ctx, tenantA, resource, action, "mallory"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// Now mallory becomes the requester (drives the gated transition). Her own earlier
	// approval must NOT count toward a 1-of-N requirement keyed on her as requester.
	if err := s.OpenIssuanceApprovalRequest(ctx, tenantA, resource, action, "mallory", 1); err != nil {
		t.Fatalf("re-open binds requester: %v", err)
	}
	if ok, err := s.HasDistinctApproval(ctx, tenantA, resource, action, "mallory", 1); err != nil || ok {
		t.Fatalf("requester's own approval counted: HasDistinctApproval = (%v, %v), want (false, nil)", ok, err)
	}
	// A genuinely distinct approver does satisfy it.
	if _, err := s.ApproveIssuance(ctx, tenantA, resource, action, "trent"); err != nil {
		t.Fatalf("distinct approve: %v", err)
	}
	if ok, _ := s.HasDistinctApproval(ctx, tenantA, resource, action, "mallory", 1); !ok {
		t.Fatal("a distinct approver must satisfy the 1-of-N requirement")
	}
}

// TestIssuanceApprovalIsolation is the AN-1 cross-tenant isolation test for the new
// data-access path: tenant B can neither see nor approve tenant A's approval request,
// and an approval recorded in A is invisible to B. RLS confines every query.
func TestIssuanceApprovalIsolation(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	const resource, action = "shared-id", "issue"
	if err := s.OpenIssuanceApprovalRequest(ctx, tenantA, resource, action, "alice", 2); err != nil {
		t.Fatalf("open (A): %v", err)
	}
	if _, err := s.ApproveIssuance(ctx, tenantA, resource, action, "bob"); err != nil {
		t.Fatalf("approve (A): %v", err)
	}

	// Tenant A sees its request and the one approval.
	a, err := s.GetIssuanceApproval(ctx, tenantA, resource, action)
	if err != nil {
		t.Fatalf("GetIssuanceApproval(A): %v", err)
	}
	if a.Requester != "alice" || a.Approvals != 1 {
		t.Fatalf("A's request = %+v, want requester=alice approvals=1", a)
	}

	// Tenant B must NOT see A's request (RLS confines the read) — even using the same
	// resource/action keys.
	if _, err := s.GetIssuanceApproval(ctx, tenantB, resource, action); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("GetIssuanceApproval(B, A's keys) = %v, want ErrNoRows (cross-tenant read denied)", err)
	}
	// And B sees zero distinct approvals for those keys.
	if ok, err := s.HasDistinctApproval(ctx, tenantB, resource, action, "alice", 1); err != nil || ok {
		t.Fatalf("HasDistinctApproval(B) = (%v, %v), want (false, nil) — A's approval must not leak to B", ok, err)
	}

	// B approving "the same" resource opens ITS OWN request (separate tenant row);
	// it does not touch A's count.
	if err := s.OpenIssuanceApprovalRequest(ctx, tenantB, resource, action, "eve", 2); err != nil {
		t.Fatalf("open (B): %v", err)
	}
	if n, err := s.ApproveIssuance(ctx, tenantB, resource, action, "frank"); err != nil || n != 1 {
		t.Fatalf("approve (B) = (%d, %v), want (1, nil) — B's count is independent of A", n, err)
	}
	// A's count is unchanged (still 1), proving no cross-tenant bleed.
	if a2, err := s.GetIssuanceApproval(ctx, tenantA, resource, action); err != nil || a2.Approvals != 1 {
		t.Fatalf("A's approvals after B activity = (%+v, %v), want approvals=1", a2, err)
	}
}
