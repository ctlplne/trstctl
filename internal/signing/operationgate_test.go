// SPDX-License-Identifier: MPL-2.0

package signing

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

type fakeOperationGate struct {
	decision OperationDecision
	err      error
	calls    int
	onCall   func()
}

func (f *fakeOperationGate) VerifyOperation(_ context.Context, _ OperationRequest) (OperationDecision, error) {
	f.calls++
	if f.onCall != nil {
		f.onCall()
	}
	return f.decision, f.err
}

func TestVerifyOperationFailsClosedWithoutAttachedGate(t *testing.T) {
	s := NewServer()
	_, err := s.VerifyOperation(context.Background(), &signerpb.OperationRequest{
		TenantId:      "tenant-1",
		Operation:     "delete",
		Preconditions: []byte("plan"),
	})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("VerifyOperation without gate: got %v, want Unimplemented", status.Code(err))
	}
}

func TestSigner_VerifiesPlanBeforeCorrectiveOp(t *testing.T) {
	req := OperationRequest{TenantID: "tenant-1", Operation: "delete", Preconditions: []byte("plan")}

	refusingGate := &fakeOperationGate{decision: OperationDecision{Approved: false, RefusalRecord: []byte("refused")}}
	refusingServer := NewServer(WithOperationGate(refusingGate))
	ran := false
	decision, err := refusingServer.gatedOperation(context.Background(), req, func(context.Context, OperationDecision) error {
		ran = true
		return nil
	})
	if err != nil {
		t.Fatalf("refused gatedOperation: %v", err)
	}
	if decision.Approved || len(decision.RefusalRecord) == 0 || ran {
		t.Fatalf("refused operation = %+v ran=%v, want signed refusal and no key op", decision, ran)
	}

	var order []string
	approvingGate := &fakeOperationGate{
		decision: OperationDecision{Approved: true, Authorization: []byte("authorized")},
		onCall: func() {
			order = append(order, "gate")
		},
	}
	approvingServer := NewServer(WithOperationGate(approvingGate))
	decision, err = approvingServer.gatedOperation(context.Background(), req, func(_ context.Context, dec OperationDecision) error {
		order = append(order, "key-op")
		if !dec.Approved || string(dec.Authorization) != "authorized" {
			t.Fatalf("key op saw decision %+v, want approved authorization", dec)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("approved gatedOperation: %v", err)
	}
	if !decision.Approved {
		t.Fatalf("approved operation = %+v, want approved", decision)
	}
	if len(order) != 2 || order[0] != "gate" || order[1] != "key-op" {
		t.Fatalf("operation order = %v, want gate before key-op", order)
	}

	failGate := &fakeOperationGate{err: errors.New("broken evidence")}
	failServer := NewServer(WithOperationGate(failGate))
	ran = false
	if _, err := failServer.gatedOperation(context.Background(), req, func(context.Context, OperationDecision) error {
		ran = true
		return nil
	}); err == nil || ran {
		t.Fatalf("gate error err=%v ran=%v, want error before key op", err, ran)
	}
}
