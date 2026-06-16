package approval

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

func TestDenyIsTerminal(t *testing.T) {
	iss := &recIssuer{}
	m := newMgr(t, iss, nil, nil, &auditsink.Recorder{}, nil)
	ctx := context.Background()
	_, _ = m.RequestIssuance(ctx, RequestSpec{ID: "r", Resource: "x", Requester: "alice"})
	r, err := m.Deny(ctx, "t1", "r", "bob", "not needed")
	if err != nil || r.State != StateDenied {
		t.Fatalf("deny = %+v (err %v)", r, err)
	}
	// Approving a denied request is a terminal no-op; it never issues.
	r2, _ := m.Approve(ctx, "t1", "r", "carol")
	if r2.State != StateDenied || iss.n != 0 {
		t.Errorf("approve mutated a denied request: state=%q issued=%d", r2.State, iss.n)
	}
	// Deny is idempotent.
	if _, err := m.Deny(ctx, "t1", "r", "x", "y"); err != nil {
		t.Errorf("second deny errored: %v", err)
	}
}

func TestUnknownRequestErrors(t *testing.T) {
	m := newMgr(t, &recIssuer{}, nil, nil, &auditsink.Recorder{}, nil)
	ctx := context.Background()
	if _, err := m.Get(ctx, "t1", "nope"); err == nil {
		t.Error("Get of unknown request should error")
	}
	if _, err := m.Approve(ctx, "t1", "nope", "bob"); err == nil {
		t.Error("Approve of unknown request should error")
	}
	if _, err := m.Deny(ctx, "t1", "nope", "bob", "x"); err == nil {
		t.Error("Deny of unknown request should error")
	}
}

func TestApproveAfterIssuedIsNoOp(t *testing.T) {
	iss := &recIssuer{}
	m := newMgr(t, iss, nil, nil, &auditsink.Recorder{}, nil)
	ctx := context.Background()
	_, _ = m.RequestIssuance(ctx, RequestSpec{ID: "r", Resource: "x", Requester: "alice", RequiredApprovals: 1})
	if _, err := m.Approve(ctx, "t1", "r", "bob"); err != nil { // issues at quorum=1
		t.Fatal(err)
	}
	r, _ := m.Approve(ctx, "t1", "r", "carol") // terminal no-op
	if r.State != StateIssued || iss.n != 1 {
		t.Errorf("approve after issued changed state/issued again: state=%q n=%d", r.State, iss.n)
	}
}

func TestDenyAfterIssuedRejected(t *testing.T) {
	iss := &recIssuer{}
	m := newMgr(t, iss, nil, nil, &auditsink.Recorder{}, nil)
	ctx := context.Background()
	_, _ = m.RequestIssuance(ctx, RequestSpec{ID: "r", Resource: "x", Requester: "alice", RequiredApprovals: 1})
	_, _ = m.Approve(ctx, "t1", "r", "bob")
	if _, err := m.Deny(ctx, "t1", "r", "carol", "too late"); err == nil {
		t.Error("denying an already-issued request should error")
	}
}
