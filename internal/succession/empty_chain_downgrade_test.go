// SPDX-License-Identifier: BUSL-1.1

package succession_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/succession"
)

// TestEmptyChainCannotBypassTheDowngradeCheck is the regression guard for the
// rollback that worked by presenting nothing.
//
// VerifyChain guarded the downgrade check with `len(chain) > 0`, so a chainless
// presentation skipped it entirely and returned nil. That is not a harmless
// no-op: rpverify.Verify seeds its Result from the GENESIS record and only
// advances it when the chain is non-empty, so a relying party that had durably
// accepted epoch 5 would resolve a chain-free presentation to the genesis key at
// epoch 0 — a rollback to a key that may have been rotated away precisely
// because it was compromised. Presenting nothing was strictly stronger than
// presenting a stale chain.
func TestEmptyChainCannotBypassTheDowngradeCheck(t *testing.T) {
	genesis, chain, _, _, _ := liveChain(t)

	// Baseline: the honest one-record chain is accepted by a verifier that has
	// accepted nothing yet, and its head is epoch 1.
	if err := succession.VerifyChain(genesis, chain, 0); err != nil {
		t.Fatalf("the honest chain does not verify: %v", err)
	}

	// A verifier that has durably accepted epoch 5 must reject a stale chain...
	if err := succession.VerifyChain(genesis, chain, 5); !errors.Is(err, succession.ErrDowngrade) {
		t.Fatalf("stale chain against last-accepted 5 = %v, want ErrDowngrade", err)
	}
	// ...and must reject the chainless version of the same rollback.
	for _, empty := range [][]succession.SuccessionRecord{nil, {}} {
		if err := succession.VerifyChain(genesis, empty, 5); !errors.Is(err, succession.ErrDowngrade) {
			t.Fatalf("empty chain against last-accepted 5 = %v, want ErrDowngrade; "+
				"omitting the chain rolls the identity back to the genesis key", err)
		}
	}
}

// TestFirstContactStillAcceptsABareGenesis guards the other direction.
// lastAccepted == 0 means the verifier has accepted nothing, which is legitimate
// first contact — federation and issuer both call VerifyChain with 0 by design —
// so the downgrade check must not fire there.
func TestFirstContactStillAcceptsABareGenesis(t *testing.T) {
	genesis, _, _, _, _ := liveChain(t)
	for _, empty := range [][]succession.SuccessionRecord{nil, {}} {
		if err := succession.VerifyChain(genesis, empty, 0); err != nil {
			t.Fatalf("first contact with a bare genesis was rejected: %v", err)
		}
	}
}
