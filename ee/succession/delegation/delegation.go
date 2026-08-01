// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package delegation implements delegated-authority succession domains (PCAS-claims-33,
// 45, 46; FIG. 8): a tree of tenant scopes, each with succession-constraint state
// (an algorithm-epoch floor). The effective constraint for a scope is the
// strongest over the scope and all its ancestors, so a constraint never loosens
// down the tree. The delegation path is bound into the succession commitment via
// the already-committed policy_ref field (so PCAS-04's commitment is unchanged).
// All hashing routes through the core internal/crypto AN-3 boundary.
package delegation

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/internal/crypto"
)

// ErrConstraintViolation is returned when a succession would violate the
// effective constraint of a scope.
var ErrConstraintViolation = errors.New("delegation: succession violates the effective constraint")

// Constraint is a scope's succession-constraint state (PCAS-claim-33): at least an
// algorithm-epoch floor.
type Constraint struct{ EpochFloor uint64 }

// Scope is a node in the delegation tree.
type Scope struct {
	ID         string
	Parent     string // "" for the root
	Constraint Constraint
}

// Tree is a delegation tree of tenant scopes.
type Tree struct{ scopes map[string]Scope }

// NewTree returns an empty delegation tree.
func NewTree() *Tree { return &Tree{scopes: map[string]Scope{}} }

// AddScope adds or replaces a scope.
func (t *Tree) AddScope(id, parent string, c Constraint) {
	t.scopes[id] = Scope{ID: id, Parent: parent, Constraint: c}
}

// Path returns the scope path from the root to id (root first).
func (t *Tree) Path(id string) ([]string, error) {
	var path []string
	seen := map[string]bool{}
	for cur := id; cur != ""; {
		s, ok := t.scopes[cur]
		if !ok {
			return nil, fmt.Errorf("delegation: unknown scope %q", cur)
		}
		if seen[cur] {
			return nil, errors.New("delegation: cycle in delegation tree")
		}
		seen[cur] = true
		path = append([]string{cur}, path...)
		cur = s.Parent
	}
	return path, nil
}

// EffectiveFloor returns the effective epoch floor for a scope: the MAX floor over
// the scope and all its ancestors, so the effective constraint never loosens down
// the tree (PCAS-claim-33 / INV-14).
func (t *Tree) EffectiveFloor(id string) (uint64, error) {
	path, err := t.Path(id)
	if err != nil {
		return 0, err
	}
	var floor uint64
	for _, sid := range path {
		if f := t.scopes[sid].Constraint.EpochFloor; f > floor {
			floor = f
		}
	}
	return floor, nil
}

// CheckSuccession refuses a succession for an identity of scope id whose target
// epoch is below the effective floor (PCAS-claim-33).
func (t *Tree) CheckSuccession(id string, targetEpoch uint64) error {
	floor, err := t.EffectiveFloor(id)
	if err != nil {
		return err
	}
	if targetEpoch < floor {
		return fmt.Errorf("%w: target epoch %d < effective floor %d for scope %q", ErrConstraintViolation, targetEpoch, floor, id)
	}
	return nil
}

// MinterConstraint adapts a Tree to the signer minter's delegation seam (INT-13,
// minter.DelegationConstraint): it enforces the effective ancestor constraint for a
// scope inside the signer, before successor keygen, and returns the canonical
// delegation-path representation to bind in the commitment. It satisfies
// minter.DelegationConstraint structurally, so the minter needs no import of this
// package.
type MinterConstraint struct{ tree *Tree }

// NewMinterConstraint returns a minter delegation constraint over tree.
func NewMinterConstraint(tree *Tree) *MinterConstraint { return &MinterConstraint{tree: tree} }

// CheckAndBind refuses a succession of scope whose target epoch is below the effective
// ancestor floor (ErrConstraintViolation), and otherwise returns the delegation-path
// representation (DelegationPolicyRef of the root→scope path) to bind in the commitment.
func (c *MinterConstraint) CheckAndBind(scope string, targetEpoch uint64) (string, error) {
	if err := c.tree.CheckSuccession(scope, targetEpoch); err != nil {
		return "", err
	}
	path, err := c.tree.Path(scope)
	if err != nil {
		return "", err
	}
	return DelegationPolicyRef(path), nil
}

// IdentityState is an identity's current scope and algorithm-epoch.
type IdentityState struct {
	Scope string
	Epoch uint64
}

// RaiseConstraint raises scope id's floor and returns the identities of that scope
// or its descendants whose current epoch now violates the raised effective floor —
// the forced-migration jobs (PCAS-claim-45).
func (t *Tree) RaiseConstraint(id string, newFloor uint64, identities map[string]IdentityState) ([]string, error) {
	s, ok := t.scopes[id]
	if !ok {
		return nil, fmt.Errorf("delegation: unknown scope %q", id)
	}
	s.Constraint.EpochFloor = newFloor
	t.scopes[id] = s

	var jobs []string
	for identityID, st := range identities {
		if !t.isDescendant(st.Scope, id) {
			continue
		}
		floor, err := t.EffectiveFloor(st.Scope)
		if err != nil {
			return nil, err
		}
		if st.Epoch < floor {
			jobs = append(jobs, identityID)
		}
	}
	sort.Strings(jobs)
	return jobs, nil
}

func (t *Tree) isDescendant(scope, ancestor string) bool {
	seen := map[string]bool{}
	for cur := scope; cur != ""; {
		if cur == ancestor {
			return true
		}
		if seen[cur] {
			return false
		}
		seen[cur] = true
		s, ok := t.scopes[cur]
		if !ok {
			return false
		}
		cur = s.Parent
	}
	return false
}

// DelegationPolicyRef binds a delegation path into the succession commitment via
// the policy_ref field (PCAS-claim-33 — the path representation is committed because
// policy_ref is a bound commitment field). Distinct paths yield distinct refs and
// hence distinct commitments.
func DelegationPolicyRef(path []string) string {
	var b bytes.Buffer
	b.WriteString("delegation/path/v1")
	for _, s := range path {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(s)))
		b.Write(l[:])
		b.WriteString(s)
	}
	return "delegation:v1:" + hex.EncodeToString(crypto.SHA256Sum(b.Bytes()))
}

// CoSignGenesis has a descendant scope's trust root co-sign the genesis of an
// identity minted at the request of a provider entity (PCAS-claim-46). It is the same
// tenant-trust-root attestation VerifyGenesis checks, with the descendant scope's
// root as the signing authority.
func CoSignGenesis(descendantRoot crypto.Signer, g succession.GenesisRecord) (succession.GenesisRecord, error) {
	gd, err := succession.GenesisDigest(g)
	if err != nil {
		return succession.GenesisRecord{}, err
	}
	sig, err := descendantRoot.Sign(gd, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return succession.GenesisRecord{}, err
	}
	g.TrustRootAtt = sig
	return g, nil
}
