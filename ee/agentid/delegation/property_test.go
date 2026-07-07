// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"math/rand"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// TestProperty_ComparatorMonotonicityReCheckedInSigner is the property the card requires:
// the gate's accept/refuse decision on a two-hop chain agrees with the AGID-01 comparator
// WithinParent for that pair (differential against the comparator). For randomly generated
// (parent, child) authority pairs with everything else valid, the gate approves IFF the
// child is within the parent -- so the comparator monotonicity is genuinely RE-CHECKED
// inside the signer, not merely trusted.
func TestProperty_ComparatorMonotonicityReCheckedInSigner(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	rng := rand.New(rand.NewSource(0xA61D04B))

	scopeUniverse := []string{"read", "write", "admin", "delete", "list"}
	randScopes := func() []string {
		var out []string
		for _, s := range scopeUniverse {
			if rng.Intn(2) == 0 {
				out = append(out, s)
			}
		}
		return out
	}

	for i := 0; i < 300; i++ {
		parentScopes := randScopes()
		childScopes := randScopes()
		parentBudget := uint64(rng.Intn(1000) + 1)
		childBudget := uint64(rng.Intn(1000) + 1)
		// Keep the DEPTH dimension always within (childDepth < parentDepth) and set each
		// hop's depth_remaining equal to its authority depth ceiling, so depth ACCOUNTING
		// (remaining <= ceiling, strict decrement) always passes and the ONLY thing that
		// can flip the gate's decision is the AUTHORITY-NARROWING comparison on the set /
		// budget dimensions. That isolates the differential against WithinParent.
		parentDepth := uint32(rng.Intn(4) + 3) // >= 3
		childDepth := uint32(rng.Intn(int(parentDepth)))
		if childDepth == parentDepth {
			childDepth = parentDepth - 1
		}

		parent := Authority{Scopes: parentScopes, Spend: Budget{Amount: parentBudget, Currency: "usd"}, Rate: Rate{Limit: 100, Per: "minute"}, Depth: parentDepth}
		child := Authority{Scopes: childScopes, Spend: Budget{Amount: childBudget, Currency: "usd"}, Rate: Rate{Limit: 100, Per: "minute"}, Depth: childDepth}

		want := WithinParent(child, parent, reg)

		rootSigner, rootDER := signerWithDER(t)
		midSigner, midDER := signerWithDER(t)
		parentRemaining := parentDepth
		childRemaining := childDepth
		hops := []hop{
			{delegatorID: "root", delegatorKeyID: "root-key", delegateID: "mid", authority: parent, depthRemaining: parentRemaining, validity: openWindow()},
			{delegatorID: "mid", delegatorKeyID: "mid-key", delegateID: "leaf", authority: child, depthRemaining: childRemaining, validity: openWindow()},
		}
		bc := buildChain(t, reg, "t1", hops, []crypto.Signer{rootSigner, midSigner}, [][]byte{rootDER, midDER})
		anchors := map[string]RootAnchor{"root-key": {PublicDER: rootDER, AuthRef: "fido2:x"}}
		f := newGateFixture(t, anchors, nil, nil, nil)
		pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: bc.envelopes})
		req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

		// Note child.Depth must also be <= parent.Depth for the authority to be within;
		// WithinParent already accounts for the Depth dimension, so `want` is exact.
		res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
		got := res.decision.Approved
		if got != want {
			t.Fatalf("iter %d: gate approved=%v but WithinParent=%v for parent=%+v child=%+v", i, got, want, parent, child)
		}
		if !got && f.keystore.keyOps() != 0 {
			t.Fatalf("iter %d: refusal performed a key op", i)
		}
	}
}
