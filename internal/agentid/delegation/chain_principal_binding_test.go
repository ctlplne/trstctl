// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// TestChainRejectsHopWhoseDelegatorIsNotTheParentsDelegate is the regression
// guard for the delegation-chain principal-binding defect.
//
// verifyChain linked hops by parent DIGEST and verified each hop's signature
// against the delegator public key carried in that same envelope. Nothing tied
// hop i's delegator to hop i-1's delegate, so a holder of any valid chain could
// append a hop naming an unrelated principal as delegator — with a correct
// parent digest and a valid, self-consistent signature — and inherit the root's
// authority.
//
// The appended hop below is signed by an attacker key and names "attacker" as
// its delegator, while the parent conferred authority on "leaf".
func TestChainRejectsHopWhoseDelegatorIsNotTheParentsDelegate(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	rootSigner, rootDER := signerWithDER(t)
	midSigner, midDER := signerWithDER(t)
	attackerSigner, attackerDER := signerWithDER(t)

	hops := []hop{
		{delegatorID: "root", delegatorKeyID: "root-key", delegateID: "mid", authority: wideAuthority(), depthRemaining: 3, validity: openWindow()},
		{delegatorID: "mid", delegatorKeyID: "mid-key", delegateID: "leaf", authority: narrowerAuthority(), depthRemaining: 2, validity: openWindow()},
		// The forged hop: its delegator is "attacker", not "leaf".
		{delegatorID: "attacker", delegatorKeyID: "attacker-key", delegateID: "attacker-target", authority: narrowerAuthority(), depthRemaining: 1, validity: openWindow()},
	}
	bc := buildChain(t, reg, "t1", hops,
		[]crypto.Signer{rootSigner, midSigner, attackerSigner},
		[][]byte{rootDER, midDER, attackerDER})

	anchors := map[string]RootAnchor{"root-key": {PublicDER: rootDER, AuthRef: "fido2:x"}}
	f := newGateFixture(t, anchors, nil, nil, nil)

	pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: bc.envelopes})
	req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "attacker-target", Preconditions: pre}

	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if res.decision.Approved {
		t.Fatal("a hop whose delegator is not the previous hop's delegate was APPROVED; " +
			"anyone holding a valid chain could append themselves and inherit the root's authority")
	}
	if res.keyOpRan || f.keystore.keyOps() != 0 {
		t.Fatalf("a refused issuance performed %d key ops, want ZERO (INV-A1)", f.keystore.keyOps())
	}
	art := decodeRefusalForTest(t, res.decision.RefusalRecord)
	if art.FailedCheck != CheckChainLinkage {
		t.Fatalf("refusal failed_check = %q, want %q", art.FailedCheck, CheckChainLinkage)
	}
	if art.HopIndex != 2 {
		t.Fatalf("refusal hop_index = %d, want 2 (the appended hop)", art.HopIndex)
	}
}

// TestChainAcceptsProperlyLinkedPrincipals keeps the guard honest: a chain whose
// every hop's delegator IS the previous hop's delegate must still verify, so the
// check cannot be satisfied by refusing all multi-hop chains.
func TestChainAcceptsProperlyLinkedPrincipals(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	rootSigner, rootDER := signerWithDER(t)
	midSigner, midDER := signerWithDER(t)

	hops := []hop{
		{delegatorID: "root", delegatorKeyID: "root-key", delegateID: "mid", authority: wideAuthority(), depthRemaining: 3, validity: openWindow()},
		{delegatorID: "mid", delegatorKeyID: "mid-key", delegateID: "leaf", authority: narrowerAuthority(), depthRemaining: 2, validity: openWindow()},
	}
	bc := buildChain(t, reg, "t1", hops,
		[]crypto.Signer{rootSigner, midSigner}, [][]byte{rootDER, midDER})

	anchors := map[string]RootAnchor{"root-key": {PublicDER: rootDER, AuthRef: "fido2:x"}}
	f := newGateFixture(t, anchors, nil, nil, nil)

	pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: bc.envelopes})
	req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if !res.decision.Approved {
		t.Fatalf("a correctly linked chain was refused: %s", string(res.decision.RefusalRecord))
	}
}
