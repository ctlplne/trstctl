// SPDX-License-Identifier: LicenseRef-trstctl-EE

package issuer_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/issuer"
	"trstctl.com/trstctl/internal/crypto"
)

func issuerChain(t *testing.T) (succession.GenesisRecord, []succession.SuccessionRecord) {
	t.Helper()
	sc, err := succession.BuildSampleChain(crypto.NewSoftwareBackend(), "spiffe://d", "spiffe://d/ca", "t")
	if err != nil {
		t.Fatal(err)
	}
	return sc.Genesis, sc.Records
}

// TestIssuerSuccession_LeafInheritsEpoch: a leaf issued under the succeeded issuer
// inherits the issuer's current algorithm-epoch, derived from the issuer's chain
// (PCAS-claim-20).
func TestIssuerSuccession_LeafInheritsEpoch(t *testing.T) {
	genesis, chain := issuerChain(t)
	head := chain[len(chain)-1].Fields.Epoch

	posture, err := issuer.PostureFromChain(genesis, chain)
	if err != nil {
		t.Fatalf("PostureFromChain: %v", err)
	}
	if posture.Epoch != head {
		t.Fatalf("issuer posture epoch = %d, want head %d", posture.Epoch, head)
	}
	leaf := issuer.IssueLeaf(posture, "leaf-1", 1)
	eff, err := issuer.EffectiveEpoch(leaf, posture)
	if err != nil {
		t.Fatal(err)
	}
	if eff != head {
		t.Fatalf("leaf effective epoch = %d, want issuer head %d", eff, head)
	}

	// A leaf issued under an EARLIER issuer posture carries the lower epoch — showing
	// the leaf inherits whatever the issuer's epoch was at issuance.
	earlier, err := issuer.PostureFromChain(genesis, chain[:1])
	if err != nil {
		t.Fatal(err)
	}
	earlyLeaf := issuer.IssueLeaf(earlier, "leaf-0", 1)
	if earlyLeaf.IssuerEpoch >= leaf.IssuerEpoch {
		t.Fatalf("earlier leaf epoch %d not below later leaf epoch %d", earlyLeaf.IssuerEpoch, leaf.IssuerEpoch)
	}

	// The projection reports the leaf's effective algorithm from the issuer chain.
	alg, epoch, err := issuer.LeafPosture(leaf, genesis, chain)
	if err != nil {
		t.Fatal(err)
	}
	if epoch != head || alg != posture.Algorithm {
		t.Fatalf("leaf posture = (%s, %d), want (%s, %d)", alg, epoch, posture.Algorithm, head)
	}
}

// TestIssuerSuccession_LeafReissueNoPerLeafRecord: re-issuing a fleet under the
// succeeded issuer produces zero per-leaf succession records; every leaf inherits the
// issuer's new epoch (PCAS-claim-20).
func TestIssuerSuccession_LeafReissueNoPerLeafRecord(t *testing.T) {
	genesis, chain := issuerChain(t)
	posture, err := issuer.PostureFromChain(genesis, chain)
	if err != nil {
		t.Fatal(err)
	}
	fleet := issuer.ReissueFleet(posture, []string{"l1", "l2", "l3", "l4", "l5"})
	if len(fleet) != 5 {
		t.Fatalf("fleet size = %d, want 5", len(fleet))
	}
	// Each leaf inherits the issuer epoch; a Leaf structurally carries NO succession
	// record — the whole fleet migrates by inheritance, zero per-leaf records.
	for _, leaf := range fleet {
		eff, err := issuer.EffectiveEpoch(leaf, posture)
		if err != nil {
			t.Fatalf("leaf %s: %v", leaf.LeafID, err)
		}
		if eff != posture.Epoch {
			t.Fatalf("leaf %s epoch %d != issuer %d", leaf.LeafID, eff, posture.Epoch)
		}
	}
}

// TestIssuerTuple_LeafCarriesEpochAndRotation: a leaf carries the (issuer-epoch,
// rotation-version) tuple (PCAS-claim-27).
func TestIssuerTuple_LeafCarriesEpochAndRotation(t *testing.T) {
	genesis, chain := issuerChain(t)
	posture, err := issuer.PostureFromChain(genesis, chain)
	if err != nil {
		t.Fatal(err)
	}
	leaf := issuer.IssueLeaf(posture, "leaf-x", 7)
	ep, rot := leaf.Tuple()
	if ep != posture.Epoch || rot != 7 {
		t.Fatalf("tuple = (%d, %d), want (%d, 7)", ep, rot, posture.Epoch)
	}
	// A leaf claiming an epoch ahead of the issuer is rejected.
	ahead := leaf
	ahead.IssuerEpoch = posture.Epoch + 1
	if _, err := issuer.EffectiveEpoch(ahead, posture); !errors.Is(err, issuer.ErrLeafAheadOfIssuer) {
		t.Fatalf("leaf ahead of issuer: got %v, want ErrLeafAheadOfIssuer", err)
	}
	// A leaf naming a different issuer is rejected.
	foreign := leaf
	foreign.IssuerID = "spiffe://d/other-ca"
	if _, err := issuer.EffectiveEpoch(foreign, posture); !errors.Is(err, issuer.ErrWrongIssuer) {
		t.Fatalf("foreign issuer: got %v, want ErrWrongIssuer", err)
	}
}

// TestIssuerSuccession_EpochMonotonic: the issuer chain obeys the same anchor /
// monotonicity guards as any identity — a gapped or mis-anchored issuer chain is
// rejected (INV-2/INV-3 at issuer granularity).
func TestIssuerSuccession_EpochMonotonic(t *testing.T) {
	genesis, chain := issuerChain(t)
	// Drop the first record: the remaining head no longer anchors to genesis.
	if _, err := issuer.PostureFromChain(genesis, chain[1:]); err == nil {
		t.Fatal("a gapped issuer chain was accepted (monotonicity/anchor guard missing)")
	}
	// The full chain is fine.
	if _, err := issuer.PostureFromChain(genesis, chain); err != nil {
		t.Fatalf("valid issuer chain rejected: %v", err)
	}
}
