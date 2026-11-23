// SPDX-License-Identifier: BUSL-1.1

package signerwiring_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/minter"
	"trstctl.com/trstctl/internal/succession/signerwiring"
)

// TestINT02_ProductionMinterResolvesSignerHeldPredecessor proves the INT-02 wiring:
// a production minter built by NewProductionMinter and attached via
// WithSuccessionMinter resolves a predecessor handle against a key the SIGNER holds
// — injected through the resolver seam at construction — and mints a valid
// succession over the transport. The predecessor is a real signer-held key created
// through the signer's own GenerateKey RPC, not a control-plane-supplied map.
func TestINT02_ProductionMinterResolvesSignerHeldPredecessor(t *testing.T) {
	authority := approvalAuthority(t)
	m, err := signerwiring.NewProductionMinter(signerwiring.Config{SignerID: "trstctl-signer-test", DualControlAuthorityPubDER: authority.Public().DER})
	if err != nil {
		t.Fatal(err)
	}
	svc := signing.NewServer(signing.WithSuccessionMinter(m))
	client := serveSigner(t, svc)

	// The predecessor key is generated INSIDE the signer and held under a handle.
	pred, err := client.GenerateKeyHandle(context.Background(), crypto.ECDSAP256, "issuer-key")
	if err != nil {
		t.Fatalf("generate predecessor in signer: %v", err)
	}

	// Succeed it over the transport; the minter resolves "issuer-key" via the
	// signer's injected custody, then generates the successor inside the signer.
	req := signing.MintRequest{
		IdentityID:               "spiffe://d/issuer",
		TenantID:                 "tenant-a",
		DeploymentScope:          "deployment-1",
		PredecessorHandle:        "issuer-key",
		AssertedPredecessorEpoch: 0,
		TargetAlgorithm:          crypto.ECDSAP384,
		PolicyRef:                "sha256:policyref",
		NotBefore:                time.Now().Add(-time.Minute).Unix(),
		NotAfter:                 time.Now().Add(time.Hour).Unix(),
	}
	req.Authorization = approveMint(t, authority, req, "int02-approval")
	res, err := client.MintSuccessor(context.Background(), req)
	if err != nil {
		t.Fatalf("mint over transport: %v", err)
	}
	rec, err := minter.DecodeRecord(res.EncodedRecord)
	if err != nil {
		t.Fatal(err)
	}
	if err := succession.VerifyRecord(rec); err != nil {
		t.Fatalf("verify record: %v", err)
	}
	if !bytes.Equal(rec.Fields.PredecessorPub, pred.Public().DER) {
		t.Fatal("record predecessor pub != the signer-held key resolved via the injected custody")
	}
	if rec.Fields.Epoch != 1 || res.SuccessorAlgorithm != crypto.ECDSAP384 {
		t.Fatalf("epoch=%d succ-alg=%q, want 1 / ECDSA-P384", rec.Fields.Epoch, res.SuccessorAlgorithm)
	}
}

func TestCR332ProductionSignerRefusesSuccessionWithoutDualControl(t *testing.T) {
	m, err := signerwiring.NewProductionMinter(signerwiring.Config{SignerID: "trstctl-signer-test"})
	if err != nil {
		t.Fatal(err)
	}
	client := serveSigner(t, signing.NewServer(signing.WithSuccessionMinter(m)))
	if _, err := client.GenerateKeyHandle(t.Context(), crypto.ECDSAP256, "cr332-predecessor"); err != nil {
		t.Fatal(err)
	}
	_, err = client.MintSuccessor(t.Context(), signing.MintRequest{
		IdentityID: "spiffe://d/cr332", TenantID: "tenant-a", DeploymentScope: "deployment-1",
		PredecessorHandle: "cr332-predecessor", AssertedPredecessorEpoch: 0,
		TargetAlgorithm: crypto.ECDSAP384, PolicyRef: "sha256:policyref",
		NotBefore: time.Now().Add(-time.Minute).Unix(), NotAfter: time.Now().Add(time.Hour).Unix(),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unapproved production succession = %v, want signer refusal", err)
	}
}

func TestCR332ProductionSignerConsumesOnlyBoundApproval(t *testing.T) {
	authority := approvalAuthority(t)
	m, err := signerwiring.NewProductionMinter(signerwiring.Config{
		SignerID: "trstctl-signer-test", DualControlAuthorityPubDER: authority.Public().DER,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := serveSigner(t, signing.NewServer(signing.WithSuccessionMinter(m)))
	if _, err := client.GenerateKeyHandle(t.Context(), crypto.ECDSAP256, "cr332-bound-predecessor"); err != nil {
		t.Fatal(err)
	}
	req := signing.MintRequest{
		IdentityID: "spiffe://d/cr332-bound", TenantID: "tenant-a", DeploymentScope: "deployment-1",
		PredecessorHandle: "cr332-bound-predecessor", AssertedPredecessorEpoch: 0,
		TargetAlgorithm: crypto.ECDSAP384, PolicyRef: "sha256:policyref",
	}
	wrong := req
	wrong.PolicyRef = "sha256:other-policy"
	req.Authorization = approveMint(t, authority, wrong, "wrong-binding")
	if _, err := client.MintSuccessor(t.Context(), req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("misbound approval = %v, want refusal", err)
	}
	req.Authorization = approveMint(t, authority, req, "correct-binding")
	if _, err := client.MintSuccessor(t.Context(), req); err != nil {
		t.Fatalf("approved succession: %v", err)
	}
}

// TestINT02_UnboundMinterFailsClosed: a production minter the signer never binds
// (constructed but not attached, so no resolver injection) refuses to mint — it
// does not fall back to any control-plane-supplied key source.
func TestINT02_UnboundMinterFailsClosed(t *testing.T) {
	m, err := signerwiring.NewProductionMinter(signerwiring.Config{SignerID: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.MintSuccessor(context.Background(), signing.MintRequest{
		IdentityID: "id", TenantID: "t", PredecessorHandle: "whatever",
		AssertedPredecessorEpoch: 0, TargetAlgorithm: crypto.ECDSAP384,
	}); err == nil {
		t.Fatal("unbound minter must fail closed (no predecessor resolver bound)")
	}
}
