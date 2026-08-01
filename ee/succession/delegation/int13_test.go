// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/delegation"
	"trstctl.com/trstctl/ee/succession/minter"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// TestINT13_MinterEnforcesDelegationConstraint proves the delegated-authority
// effective constraint is enforced INSIDE the minter, before keygen (PCAS-claim-33): a
// succession whose target epoch is below the effective ancestor floor is refused
// (ErrDelegation), and a compliant one binds the delegation path in the v2 commitment.
func TestINT13_MinterEnforcesDelegationConstraint(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	pred, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}

	// Tree: an ancestor scope "root" imposes an epoch floor; "app" is a descendant that
	// cannot undercut it.
	tree := delegation.NewTree()
	tree.AddScope("root", "", delegation.Constraint{EpochFloor: 5})
	tree.AddScope("app", "root", delegation.Constraint{EpochFloor: 0})
	dc := delegation.NewMinterConstraint(tree)

	m, err := minter.New(int13Resolver{"pred": pred}, be, int13Floor(), minter.WithCommitmentV2(), minter.WithDelegation(dc))
	if err != nil {
		t.Fatal(err)
	}
	req := signing.MintRequest{
		IdentityID: "id", TenantID: "t", DeploymentScope: "d",
		PredecessorHandle: "pred", AssertedPredecessorEpoch: 0, TargetAlgorithm: crypto.ECDSAP384,
		PolicyRef: "p", DelegationScope: "app",
	}

	// Target epoch 1 < effective ancestor floor 5 -> refused before keygen.
	if _, err := m.MintSuccessor(context.Background(), req); !errors.Is(err, minter.ErrDelegation) {
		t.Fatalf("constraint-violating mint err = %v, want ErrDelegation", err)
	}

	// Lower the ancestor floor to 1; now epoch 1 is compliant and the delegation path is
	// bound in the commitment.
	tree.AddScope("root", "", delegation.Constraint{EpochFloor: 1})
	res, err := m.MintSuccessor(context.Background(), req)
	if err != nil {
		t.Fatalf("compliant mint: %v", err)
	}
	rec, err := minter.DecodeRecord(res.EncodedRecord)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Fields.CommitmentVersion < 2 {
		t.Fatal("record is not v2")
	}
	if rec.Fields.DelegationPath != delegation.DelegationPolicyRef([]string{"root", "app"}) {
		t.Fatalf("delegation path bound = %q, want %q", rec.Fields.DelegationPath, delegation.DelegationPolicyRef([]string{"root", "app"}))
	}
	if err := succession.VerifyRecord(rec); err != nil {
		t.Fatalf("v2 record with bound delegation path failed to verify: %v", err)
	}
}

type int13Resolver map[string]crypto.Signer

func (r int13Resolver) Resolve(h string) (crypto.Signer, error) {
	s, ok := r[h]
	if !ok {
		return nil, errors.New("no handle")
	}
	return s, nil
}

type int13FloorStore struct{ m map[string]uint64 }

func int13Floor() *int13FloorStore { return &int13FloorStore{m: map[string]uint64{}} }
func (f *int13FloorStore) Load() (map[string]uint64, error) {
	out := map[string]uint64{}
	for k, v := range f.m {
		out[k] = v
	}
	return out, nil
}
func (f *int13FloorStore) Advance(id string, e uint64) error { f.m[id] = e; return nil }
