package ephemeral

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
)

func TestEphemeralNewValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("empty TenantID accepted")
	}
	v, _ := attest.NewVerifier(attest.Config{TenantID: "t1", Attestors: []attest.Attestor{stubAtt{}}})
	if _, err := New(Config{TenantID: "t1", Verifier: v}); err == nil {
		t.Error("missing Sign func accepted")
	}
}

func TestEphemeralRequestValidation(t *testing.T) {
	iss, _ := newTestIssuer(t, nil, &auditsink.Recorder{})
	wl, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer wl.Destroy()
	ctx := context.Background()
	if _, err := iss.Issue(ctx, Request{Method: "stub", Payload: []byte("genuine"), PublicKeyDER: wl.Public().DER}); err == nil {
		t.Error("missing Idempotency-Key accepted")
	}
	if _, err := iss.Issue(ctx, Request{Method: "stub", Payload: []byte("genuine"), IdempotencyKey: "k"}); err == nil {
		t.Error("missing public key accepted")
	}
}
