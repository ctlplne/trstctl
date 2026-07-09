// SPDX-License-Identifier: MPL-2.0

package signing

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

type fakeGatedDestroyer struct {
	decision GatedDestroyDecision
	err      error
	onCall   func()
	seen     GatedDestroyRequest
}

func (f *fakeGatedDestroyer) VerifyGatedDestroy(_ context.Context, req GatedDestroyRequest) (GatedDestroyDecision, error) {
	f.seen = req
	if f.onCall != nil {
		f.onCall()
	}
	if f.err != nil {
		return GatedDestroyDecision{}, f.err
	}
	return f.decision, nil
}

func TestGate_VerifyBeforeDestroyOrdering(t *testing.T) {
	ctx := context.Background()
	req := GatedDestroyRequest{
		TenantID:       "tenant-a",
		Handle:         "signer-handle-1",
		SubjectRef:     "key://tenant-a/root",
		LedgerPosition: 7,
	}

	t.Run("refusal does not reach destroy", func(t *testing.T) {
		var order []string
		s := NewServer(WithGatedDestruction(&fakeGatedDestroyer{
			decision: GatedDestroyDecision{Approved: false, RefusalRecord: []byte("signed-refusal")},
			onCall: func() {
				order = append(order, "verify")
			},
		}))
		decision, err := s.gatedDestroy(ctx, req, func(context.Context, string) error {
			order = append(order, "destroy")
			return nil
		})
		if err != nil {
			t.Fatalf("gatedDestroy refusal: %v", err)
		}
		if decision.Approved || string(decision.RefusalRecord) != "signed-refusal" {
			t.Fatalf("decision = %+v, want signed refusal", decision)
		}
		if len(order) != 1 || order[0] != "verify" {
			t.Fatalf("order = %v, want [verify] only", order)
		}
	})

	t.Run("approval verifies before local destroy", func(t *testing.T) {
		var order []string
		s := NewServer(WithGatedDestruction(&fakeGatedDestroyer{
			decision: GatedDestroyDecision{Approved: true, Authorization: []byte("ok")},
			onCall: func() {
				order = append(order, "verify")
			},
		}))
		decision, err := s.gatedDestroy(ctx, req, func(_ context.Context, handle string) error {
			order = append(order, "destroy")
			if handle != req.Handle {
				t.Fatalf("destroy handle = %q, want %q", handle, req.Handle)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("gatedDestroy approval: %v", err)
		}
		if !decision.Approved {
			t.Fatalf("decision = %+v, want approved", decision)
		}
		if len(order) != 2 || order[0] != "verify" || order[1] != "destroy" {
			t.Fatalf("order = %v, want [verify destroy]", order)
		}
	})

	t.Run("verifier error does not reach destroy", func(t *testing.T) {
		var order []string
		sentinel := errors.New("bad evidence")
		s := NewServer(WithGatedDestruction(&fakeGatedDestroyer{
			err: sentinel,
			onCall: func() {
				order = append(order, "verify")
			},
		}))
		_, err := s.gatedDestroy(ctx, req, func(context.Context, string) error {
			order = append(order, "destroy")
			return nil
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("gatedDestroy error = %v, want %v", err, sentinel)
		}
		if len(order) != 1 || order[0] != "verify" {
			t.Fatalf("order = %v, want [verify] only", order)
		}
	})
}

func TestGatedDestroyRPCRefusalKeepsKeyAndApprovalDestroysKey(t *testing.T) {
	ctx := context.Background()
	req := GatedDestroyRequest{
		TenantID:             "tenant-a",
		Handle:               "gated-rpc-key",
		SubjectRef:           "key://tenant-a/root",
		AssertedFinalEpoch:   9,
		LedgerPosition:       11,
		RequiredSetDigest:    []byte("required-digest"),
		SatisfactionEvidence: []byte("ledger-segment"),
	}

	refusingGate := &fakeGatedDestroyer{
		decision: GatedDestroyDecision{Approved: false, RefusalRecord: []byte("signed-refusal")},
	}
	refusingServer := NewServer(WithGatedDestruction(refusingGate))
	generateGatedDestroyKey(t, ctx, refusingServer, req.Handle)
	refused, err := refusingServer.GatedDestroy(ctx, gatedDestroyRequestToProto(req))
	if err != nil {
		t.Fatalf("GatedDestroy refusal: %v", err)
	}
	if refused.GetApproved() || string(refused.GetRefusalRecord()) != "signed-refusal" {
		t.Fatalf("refusal response = %+v, want signed refusal", refused)
	}
	if !reflect.DeepEqual(refusingGate.seen.RequiredSetDigest, req.RequiredSetDigest) {
		t.Fatalf("gate saw digest %q, want %q", refusingGate.seen.RequiredSetDigest, req.RequiredSetDigest)
	}
	if _, err := refusingServer.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: req.Handle}}); err != nil {
		t.Fatalf("refused GatedDestroy removed key: %v", err)
	}

	approvingGate := &fakeGatedDestroyer{
		decision: GatedDestroyDecision{Approved: true, Authorization: []byte("destroy-ok"), Evidence: []byte("approved-evidence")},
	}
	approvingServer := NewServer(WithGatedDestruction(approvingGate))
	generateGatedDestroyKey(t, ctx, approvingServer, req.Handle)
	approved, err := approvingServer.GatedDestroy(ctx, gatedDestroyRequestToProto(req))
	if err != nil {
		t.Fatalf("GatedDestroy approval: %v", err)
	}
	if !approved.GetApproved() || string(approved.GetAuthorization()) != "destroy-ok" || string(approved.GetEvidence()) != "approved-evidence" {
		t.Fatalf("approval response = %+v, want approval material", approved)
	}
	_, err = approvingServer.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: req.Handle}})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("approved GatedDestroy lookup = %v, want NotFound", status.Code(err))
	}
}

func TestGatedDestroyProtoRoundTripAndValidation(t *testing.T) {
	req := GatedDestroyRequest{
		TenantID:             "tenant-a",
		Handle:               "handle-a",
		SubjectRef:           "key://tenant-a/root",
		AssertedFinalEpoch:   42,
		LedgerPosition:       55,
		RequiredSet:          []byte("required"),
		RequiredSetDigest:    []byte("required-digest"),
		SatisfiedSet:         []byte("satisfied"),
		SatisfactionEvidence: []byte("ledger-segment"),
		Authorization:        []byte("authz"),
		Approvals:            []byte("approvals"),
		AuditChainHead:       []byte("audit-head"),
		Context:              []byte("ctx"),
	}
	pb := gatedDestroyRequestToProto(req)
	req.RequiredSet[0] = 'X'
	got, err := gatedDestroyRequestFromProto(pb)
	if err != nil {
		t.Fatalf("gatedDestroyRequestFromProto: %v", err)
	}
	if got.TenantID != "tenant-a" || got.Handle != "handle-a" || got.SubjectRef != "key://tenant-a/root" || got.AssertedFinalEpoch != 42 || got.LedgerPosition != 55 {
		t.Fatalf("round-trip scalars = %+v", got)
	}
	if !bytes.Equal(got.RequiredSet, []byte("required")) || !bytes.Equal(got.AuditChainHead, []byte("audit-head")) {
		t.Fatalf("round-trip bytes = %+v", got)
	}
	pb.RequiredSet[0] = 'Y'
	if got.RequiredSet[0] != 'r' {
		t.Fatal("gatedDestroyRequestFromProto must clone byte slices")
	}

	decision := GatedDestroyDecision{
		Approved:      true,
		RefusalRecord: []byte("refusal"),
		Authorization: []byte("authorization"),
		Evidence:      []byte("evidence"),
	}
	if !reflect.DeepEqual(gatedDestroyDecisionFromProto(gatedDestroyDecisionToProto(decision)), decision) {
		t.Fatal("gated destroy decision proto round-trip mismatch")
	}

	tests := []struct {
		name string
		req  *signerpb.GatedDestroyRequest
	}{
		{name: "nil", req: nil},
		{name: "missing tenant", req: &signerpb.GatedDestroyRequest{Handle: &signerpb.KeyHandle{Id: "h"}, SubjectRef: "s", LedgerPosition: 1}},
		{name: "missing handle", req: &signerpb.GatedDestroyRequest{TenantId: "t", SubjectRef: "s", LedgerPosition: 1}},
		{name: "missing subject", req: &signerpb.GatedDestroyRequest{TenantId: "t", Handle: &signerpb.KeyHandle{Id: "h"}, LedgerPosition: 1}},
		{name: "missing ledger position", req: &signerpb.GatedDestroyRequest{TenantId: "t", Handle: &signerpb.KeyHandle{Id: "h"}, SubjectRef: "s"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := gatedDestroyRequestFromProto(tc.req); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("validation error = %v, want InvalidArgument", err)
			}
		})
	}
}

func generateGatedDestroyKey(t *testing.T, ctx context.Context, s *Server, handle string) {
	t.Helper()
	_, err := s.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm:   signerpb.Algorithm_ALGORITHM_ECDSA_P256,
		RequestedId: handle,
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
}
