// SPDX-License-Identifier: MPL-2.0

package approval

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
)

type recIssuer struct{ n int }

func (r *recIssuer) Issue(_ context.Context, _, reqID, _ string) (string, error) {
	r.n++
	return "cred-" + reqID, nil
}

type recoveringIssuer struct {
	issues     int
	recoveries int
}

func (r *recoveringIssuer) Issue(_ context.Context, _, reqID, _ string) (string, error) {
	r.issues++
	return "cred-" + reqID, nil
}

func (r *recoveringIssuer) RecoverIssuance(_ context.Context, _, reqID, _ string) (string, bool, error) {
	r.recoveries++
	return "cred-" + reqID, true, nil
}

type failNthSaveStore struct {
	*MemoryStore
	saves  int
	failAt int
}

func (s *failNthSaveStore) Save(ctx context.Context, req Request) error {
	s.saves++
	if s.saves == s.failAt {
		return errors.New("injected save failure")
	}
	return s.MemoryStore.Save(ctx, req)
}

type policyFn func(ctx context.Context, tenantID, reqID, approver string) (bool, string)

func (p policyFn) CanApprove(ctx context.Context, t, r, a string) (bool, string) {
	return p(ctx, t, r, a)
}

func newMgr(t *testing.T, iss Issuer, pol ApproverPolicy, rec auditsink.Auditor, clock func() time.Time) *Manager {
	t.Helper()
	m, err := New(Config{
		TenantID: "t1", Store: NewMemoryStore(), Issuer: iss, Policy: pol,
		Audit: rec, Clock: clock, DefaultTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRequiresApprovalBeforeIssuance(t *testing.T) {
	iss := &recIssuer{}
	m := newMgr(t, iss, nil, &auditsink.Recorder{}, nil)
	req, err := m.RequestIssuance(context.Background(), RequestSpec{ID: "r1", Resource: "prod-cert", Requester: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if req.State != StateAwaitingApproval {
		t.Errorf("state = %q, want awaiting", req.State)
	}
	if iss.n != 0 {
		t.Error("credential issued before approval")
	}
}

func TestDualControlIssuesAtQuorumAndAuditsChain(t *testing.T) {
	iss := &recIssuer{}
	rec := &auditsink.Recorder{}
	m := newMgr(t, iss, nil, rec, nil)
	ctx := context.Background()
	if _, err := m.RequestIssuance(ctx, RequestSpec{ID: "r1", Resource: "prod-cert", Requester: "alice"}); err != nil {
		t.Fatal(err)
	}
	r, _ := m.Approve(ctx, "t1", "r1", "bob")
	if r.State != StateAwaitingApproval || iss.n != 0 {
		t.Fatalf("after 1/2 approvals: state=%q issued=%d, want awaiting/0", r.State, iss.n)
	}
	r, _ = m.Approve(ctx, "t1", "r1", "carol")
	if r.State != StateIssued || iss.n != 1 {
		t.Fatalf("after 2/2 approvals: state=%q issued=%d, want issued/1", r.State, iss.n)
	}
	if rec.Count("approval.requested") != 1 || rec.Count("approval.approved") != 2 || rec.Count("approval.issued") != 1 {
		t.Errorf("audit chain incomplete: %d/%d/%d", rec.Count("approval.requested"), rec.Count("approval.approved"), rec.Count("approval.issued"))
	}
}

func TestSelfApprovalDenied(t *testing.T) {
	iss := &recIssuer{}
	m := newMgr(t, iss, nil, &auditsink.Recorder{}, nil)
	ctx := context.Background()
	_, _ = m.RequestIssuance(ctx, RequestSpec{ID: "r1", Resource: "x", Requester: "alice"})
	if _, err := m.Approve(ctx, "t1", "r1", "alice"); err == nil {
		t.Error("requester was allowed to approve own request (dual control violated)")
	}
	if iss.n != 0 {
		t.Error("issued despite only a self-approval")
	}
}

func TestPolicyScopedApprover(t *testing.T) {
	rec := &auditsink.Recorder{}
	pol := policyFn(func(_ context.Context, _, _, approver string) (bool, string) {
		if approver == "mallory" {
			return false, "not an approver for this class"
		}
		return true, ""
	})
	m := newMgr(t, &recIssuer{}, pol, rec, nil)
	ctx := context.Background()
	_, _ = m.RequestIssuance(ctx, RequestSpec{ID: "r1", Resource: "x", Requester: "alice"})
	if _, err := m.Approve(ctx, "t1", "r1", "mallory"); err == nil {
		t.Error("out-of-scope approver was permitted")
	}
	if rec.Count("approval.refused") != 1 {
		t.Error("refusal not audited")
	}
}

func TestGrantExpires(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	iss := &recIssuer{}
	m := newMgr(t, iss, nil, &auditsink.Recorder{}, clock)
	ctx := context.Background()
	if _, err := m.RequestIssuance(ctx, RequestSpec{ID: "r1", Resource: "x", Requester: "alice", TTL: time.Minute}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute) // past the grant window
	if _, err := m.Approve(ctx, "t1", "r1", "bob"); err == nil {
		t.Error("approved an expired request (time-bound not enforced)")
	}
	got, _ := m.Get(ctx, "t1", "r1")
	if got.State != StateExpired {
		t.Errorf("state = %q, want expired", got.State)
	}
	if iss.n != 0 {
		t.Error("issued an expired request")
	}
}

func TestApproveIsIdempotent(t *testing.T) {
	m := newMgr(t, &recIssuer{}, nil, &auditsink.Recorder{}, nil)
	ctx := context.Background()
	_, _ = m.RequestIssuance(ctx, RequestSpec{ID: "r1", Resource: "x", Requester: "alice"})
	_, _ = m.Approve(ctx, "t1", "r1", "bob")
	r, _ := m.Approve(ctx, "t1", "r1", "bob") // duplicate
	if approveCount(r) != 1 {
		t.Errorf("duplicate approval counted twice: %d", approveCount(r))
	}
}

func TestApproveDoesNotReissueAfterPostIssueSaveFailure(t *testing.T) {
	ctx := context.Background()
	store := &failNthSaveStore{MemoryStore: NewMemoryStore(), failAt: 3}
	issuer := &recoveringIssuer{}
	m, err := New(Config{
		TenantID: "t1", Store: store, Issuer: issuer,
		Audit: &auditsink.Recorder{}, DefaultTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.RequestIssuance(ctx, RequestSpec{
		ID: "crash-window", Resource: "prod-cert", Requester: "alice", RequiredApprovals: 1,
	}); err != nil {
		t.Fatal(err)
	}

	first, err := m.Approve(ctx, "t1", "crash-window", "bob")
	if err == nil || first.State != StateIssued || first.CredentialID != "cred-crash-window" {
		t.Fatalf("post-issue save failure = (%+v, %v), want accurate issued result plus persistence error", first, err)
	}
	durable, ok, err := store.Get(ctx, "t1", "crash-window")
	if err != nil || !ok || durable.State != StateIssuing || durable.CredentialID != "" {
		t.Fatalf("durable crash state = (%+v, %v, %v), want issuing without guessed result", durable, ok, err)
	}

	recovered, err := m.Approve(ctx, "t1", "crash-window", "bob")
	if err != nil {
		t.Fatalf("recover issuance result: %v", err)
	}
	if recovered.State != StateIssued || recovered.CredentialID != "cred-crash-window" {
		t.Fatalf("recovered request = %+v", recovered)
	}
	if issuer.issues != 1 || issuer.recoveries != 1 {
		t.Fatalf("issue/recovery calls = %d/%d, want 1/1 (retry must not reissue)", issuer.issues, issuer.recoveries)
	}
}
