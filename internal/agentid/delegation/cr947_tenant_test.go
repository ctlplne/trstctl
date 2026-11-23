// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// A root key may be explicitly installed in two tenants. A signature over a
// tenant-A record must not become a tenant-B delegation merely because both
// floors hold the same public key under the same key ID.
func TestCR947SignedRecordTenantMustMatchSignerRequest(t *testing.T) {
	envs, anchors, _ := singleAnchorChain(t, nil, "tenant-A", "operator:root-approval")
	gate, _, err := NewSignerGate(SignerConfig{
		SignerID:      "test-signer",
		TenantAnchors: map[string]map[string]RootAnchor{"tenant-A": anchors, "tenant-B": anchors},
		Revocations:   NeverRevoked{},
	})
	if err != nil {
		t.Fatal(err)
	}
	pre, err := encodePreconditionsForTest(PreconditionsBody{Chain: envs})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		requestTenant string
		wantApproved  bool
	}{
		{requestTenant: "tenant-A", wantApproved: true},
		{requestTenant: "tenant-B", wantApproved: false},
	} {
		t.Run(tc.requestTenant, func(t *testing.T) {
			decision, err := gate.VerifyIssuancePreconditions(backgroundCtx(), signing.IssuancePreconditions{
				TenantID: tc.requestTenant, TrustAnchorRef: "leaf", Preconditions: pre,
			})
			if err != nil {
				t.Fatal(err)
			}
			if decision.Approved != tc.wantApproved {
				t.Fatalf("signed tenant-A record approved=%v for %s request; want %v", decision.Approved, tc.requestTenant, tc.wantApproved)
			}
		})
	}
}

func TestCR947TenantScopedTrustNeverFallsBackToGlobalAnchor(t *testing.T) {
	anchor := RootAnchor{PublicDER: []byte{1, 2, 3}, AuthRef: "operator:root"}
	store := &TrustStore{
		anchors:       map[string]RootAnchor{"root": anchor},
		tenantAnchors: map[string]map[string]RootAnchor{"tenant-A": {"root": anchor}},
	}
	if _, ok := store.AnchorForTenant("tenant-A", "root"); !ok {
		t.Fatal("tenant-A lost its explicit root")
	}
	if _, ok := store.AnchorForTenant("tenant-B", "root"); ok {
		t.Fatal("tenant-B inherited the deployment-wide root without a tenant-scoped install")
	}
}

func TestCR947EverySignedHopCarriesTheIssuanceTenant(t *testing.T) {
	rootSigner, rootDER := signerWithDER(t)
	childSigner, childDER := signerWithDER(t)
	chain := buildChain(t, nil, "tenant-A", []hop{
		{delegatorID: "root", delegatorKeyID: "root-key", delegateID: "child", authority: wideAuthority(), depthRemaining: 3, validity: openWindow()},
		{delegatorID: "child", delegatorKeyID: "child-key", delegateID: "leaf", authority: narrowerAuthority(), depthRemaining: 2, validity: openWindow()},
	}, []crypto.Signer{rootSigner, childSigner}, [][]byte{rootDER, childDER})
	// Keep the parent linkage and sign the child's foreign tenant with its real
	// delegated key. This is a cryptographically valid hop with the wrong scope.
	child := chain.envelopes[1].Record
	child.TenantID = "tenant-B"
	var err error
	chain.envelopes[1].Record, err = child.Sign(childSigner, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := newGateFixture(t, map[string]RootAnchor{"root-key": {PublicDER: rootDER, AuthRef: "operator:root"}}, nil, nil, nil)
	pre, err := encodePreconditionsForTest(PreconditionsBody{Chain: chain.envelopes})
	if err != nil {
		t.Fatal(err)
	}
	res := runGatedIssue(t, f.log, f.gate, signing.IssuancePreconditions{
		TenantID: "tenant-A", TrustAnchorRef: "leaf", Preconditions: pre,
	}, f.mintKeyOp(t))
	if res.decision.Approved || res.keyOpRan || f.keystore.keyOps() != 0 {
		t.Fatal("foreign-tenant child hop reached the signer key operation")
	}
	art := decodeRefusalForTest(t, res.decision.RefusalRecord)
	if art.FailedCheck != CheckTenantBinding || art.HopIndex != 1 {
		t.Fatalf("refusal check=%q hop=%d, want tenant_binding at hop 1", art.FailedCheck, art.HopIndex)
	}
}
