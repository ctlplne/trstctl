// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/delegation"
	"trstctl.com/trstctl/ee/succession/minter"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

func tree() *delegation.Tree {
	t := delegation.NewTree()
	t.AddScope("org", "", delegation.Constraint{EpochFloor: 1})
	t.AddScope("team", "org", delegation.Constraint{EpochFloor: 0})
	t.AddScope("app", "team", delegation.Constraint{EpochFloor: 2})
	return t
}

// TestDelegation_EffectiveConstraintNeverLoosens: the effective floor is
// non-decreasing down the tree (claim 33 / INV-14).
func TestDelegation_EffectiveConstraintNeverLoosens(t *testing.T) {
	tr := tree()
	path, err := tr.Path("app")
	if err != nil {
		t.Fatal(err)
	}
	var prev uint64
	for _, s := range path {
		f, err := tr.EffectiveFloor(s)
		if err != nil {
			t.Fatal(err)
		}
		if f < prev {
			t.Fatalf("effective floor loosened at scope %q: %d < %d", s, f, prev)
		}
		prev = f
	}
	if f, _ := tr.EffectiveFloor("app"); f != 2 {
		t.Fatalf("app effective floor = %d, want 2", f)
	}
	if f, _ := tr.EffectiveFloor("team"); f != 1 {
		t.Fatalf("team effective floor = %d, want 1 (inherited from org)", f)
	}
}

// TestDelegation_RefusesViolation: a succession below the effective floor is
// refused (claim 33).
func TestDelegation_RefusesViolation(t *testing.T) {
	tr := tree()
	if err := tr.CheckSuccession("app", 1); !errors.Is(err, delegation.ErrConstraintViolation) {
		t.Fatalf("epoch 1 at app (floor 2): got %v, want ErrConstraintViolation", err)
	}
	if err := tr.CheckSuccession("app", 2); err != nil {
		t.Fatalf("epoch 2 at app refused: %v", err)
	}
	if err := tr.CheckSuccession("app", 3); err != nil {
		t.Fatalf("epoch 3 at app refused: %v", err)
	}
}

func commitFields(policyRef string) succession.CommitmentFields {
	return succession.CommitmentFields{
		DeploymentScope: "d", IdentityID: "app/db", TenantID: "app",
		PredecessorEpoch: 0, Epoch: 1,
		PredecessorAlg: crypto.ECDSAP256, PredecessorPub: []byte{1},
		SuccessorAlg: crypto.ECDSAP384, SuccessorPub: []byte{2},
		PolicyRef: policyRef, HashAlg: succession.HashAlgSHA256, NotBefore: 1, NotAfter: 2,
	}
}

// TestDelegation_PathBoundInCommitment: the delegation path is bound into the
// commitment via policy_ref; distinct paths yield distinct commitments (claim 33).
func TestDelegation_PathBoundInCommitment(t *testing.T) {
	r1 := delegation.DelegationPolicyRef([]string{"org", "team", "app"})
	r2 := delegation.DelegationPolicyRef([]string{"org", "team2", "app"})
	if r1 == r2 {
		t.Fatal("distinct delegation paths produced the same policy_ref")
	}
	if r1 != delegation.DelegationPolicyRef([]string{"org", "team", "app"}) {
		t.Fatal("policy_ref not deterministic")
	}
	c1, err := succession.Commit(commitFields(r1))
	if err != nil {
		t.Fatal(err)
	}
	c2, err := succession.Commit(commitFields(r2))
	if err != nil {
		t.Fatal(err)
	}
	if string(c1) == string(c2) {
		t.Fatal("distinct delegation paths yield equal commitments (path not bound)")
	}
}

// TestDelegation_RaiseConstraintGeneratesJobs: raising an ancestor floor produces
// forced-migration jobs for violating descendants (claim 45).
func TestDelegation_RaiseConstraintGeneratesJobs(t *testing.T) {
	tr := tree()
	tr.AddScope("other", "", delegation.Constraint{})
	identities := map[string]delegation.IdentityState{
		"app/db":    {Scope: "app", Epoch: 1},
		"team/svc":  {Scope: "team", Epoch: 5},
		"unrelated": {Scope: "other", Epoch: 1},
	}
	jobs, err := tr.RaiseConstraint("org", 3, identities)
	if err != nil {
		t.Fatal(err)
	}
	// org floor -> 3. app effective = max(3,0,2)=3, epoch 1 < 3 => job. team
	// effective = 3, svc epoch 5 => no job. unrelated is not a descendant of org.
	if len(jobs) != 1 || jobs[0] != "app/db" {
		t.Fatalf("jobs = %v, want [app/db]", jobs)
	}
}

// --- provider mint (claim 46) ----------------------------------------------

type mapResolver map[string]crypto.Signer

func (r mapResolver) Resolve(h string) (crypto.Signer, error) {
	s, ok := r[h]
	if !ok {
		return nil, errors.New("no handle")
	}
	return s, nil
}

type memFloor struct {
	mu sync.Mutex
	m  map[string]uint64
}

func newMemFloor() *memFloor { return &memFloor{m: map[string]uint64{}} }
func (f *memFloor) Load() (map[string]uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]uint64{}
	for k, v := range f.m {
		out[k] = v
	}
	return out, nil
}
func (f *memFloor) Advance(id string, e uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[id] = e
	return nil
}

// TestDelegation_ProviderMint: a provider mints a succession for a descendant
// identity; the record binds the delegation path and verifies (claim 46).
func TestDelegation_ProviderMint(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	pred, _ := be.GenerateKey(crypto.ECDSAP256)
	m, err := minter.New(mapResolver{"pred": pred}, be, newMemFloor())
	if err != nil {
		t.Fatal(err)
	}
	path := []string{"org", "team", "app"}
	req := signing.MintRequest{
		IdentityID: "app/db", TenantID: "app", DeploymentScope: "d",
		PredecessorHandle: "pred", AssertedPredecessorEpoch: 0, TargetAlgorithm: crypto.ECDSAP384,
		PolicyRef: delegation.DelegationPolicyRef(path), NotBefore: 1, NotAfter: 1000,
	}
	res, err := m.MintSuccessor(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := minter.DecodeRecord(res.EncodedRecord)
	if rec.Fields.PolicyRef != delegation.DelegationPolicyRef(path) {
		t.Fatal("minted record does not bind the delegation path")
	}
	if err := succession.VerifyRecord(rec); err != nil {
		t.Fatalf("delegated record does not verify: %v", err)
	}
}

// TestDelegation_DescendantRootCoSignsGenesis: the descendant scope's trust root
// co-signs the identity's genesis; it verifies under that root (claim 46).
func TestDelegation_DescendantRootCoSignsGenesis(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	descendantRoot, _ := be.GenerateKey(crypto.ECDSAP256)
	k0, _ := be.GenerateKey(crypto.ECDSAP256)
	g := succession.GenesisRecord{
		DeploymentScope: "d", IdentityID: "app/db", TenantID: "app",
		Algorithm: crypto.ECDSAP256, PublicKey: k0.Public().DER, Epoch: 0,
	}
	signed, err := delegation.CoSignGenesis(descendantRoot, g)
	if err != nil {
		t.Fatal(err)
	}
	if err := succession.VerifyGenesis(descendantRoot.Public().DER, signed); err != nil {
		t.Fatalf("descendant-root co-signed genesis rejected: %v", err)
	}
	other, _ := be.GenerateKey(crypto.ECDSAP256)
	if err := succession.VerifyGenesis(other.Public().DER, signed); err == nil {
		t.Fatal("genesis verified under the wrong root")
	}
}
