// SPDX-License-Identifier: BUSL-1.1

package retirement

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

type cr012CheckingSigner struct {
	verifier *crypto.SignAuthorizer
	called   bool
}

func (s *cr012CheckingSigner) GatedDestroy(_ context.Context, req signing.GatedDestroyRequest) (signing.GatedDestroyDecision, error) {
	s.called = true
	intent, err := signing.GatedDestroyIntent(req)
	if err != nil || !s.verifier.Verify(intent, req.Authorization) {
		return signing.GatedDestroyDecision{}, errors.New("worker sent a destruction request without exact independent approval")
	}
	return signing.GatedDestroyDecision{Approved: true}, nil
}

func TestCR012RetirementWorkerAuthorizesExactGatedDestroyRequest(t *testing.T) {
	authz, err := crypto.NewSignAuthorizer([]byte("cr012 independent approval secret"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.Destroy)
	request := signing.GatedDestroyRequest{
		TenantID: "11111111-1111-4111-8111-111111111111", Handle: "ca-hierarchy-cr012",
		SubjectRef: "authority-cr012", AssertedFinalEpoch: 1, LedgerPosition: 2,
		SatisfactionEvidence: []byte("frozen ledger"), AuditChainHead: []byte("head"),
		Context: []byte("finalization"),
	}
	signer := &cr012CheckingSigner{verifier: authz}
	handler := &Handler{signer: signer, authorizer: authz}
	decision, err := handler.authorizeAndDestroy(context.Background(), request)
	if err != nil || !decision.Approved || !signer.called {
		t.Fatalf("retirement worker did not send an independently authorized request: decision=%+v called=%t err=%v", decision, signer.called, err)
	}
	signer.called = false
	handler.authorizer = nil
	if _, err := handler.authorizeAndDestroy(context.Background(), request); err == nil || signer.called {
		t.Fatalf("missing independent approval did not fail before contacting signer: called=%t err=%v", signer.called, err)
	}
}
