// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package issuer implements issuer-level (authority) succession (claims 20, 27): the
// issuing CA / intermediate is itself a succession-managed NHI whose chain is an
// ordinary PCAS-04 chain. End-entity leaves issued under it INHERIT the issuer's
// algorithm-epoch and carry an (issuer-epoch, rotation-version) tuple, so a whole
// fleet of short-lived leaves migrates by ordinary re-issuance with NO per-leaf
// succession record. A leaf's effective algorithm-epoch derives from its issuer's
// chain; the relying party rejects a leaf whose carried issuer epoch is stale
// (ee/rpverify.AcceptLeafTuple). The issuer chain obeys the same monotonicity and
// anchor guards as any identity (INV-2/INV-3), via ee/succession.VerifyChain.
package issuer

import (
	"errors"
	"fmt"

	"trstctl.com/trstctl/ee/succession"
)

// Errors.
var (
	ErrWrongIssuer       = errors.New("issuer: leaf names a different issuer than the posture")
	ErrLeafAheadOfIssuer = errors.New("issuer: leaf claims an issuer epoch ahead of the issuer's current epoch")
)

// Leaf is an end-entity credential issued under a succession-managed issuer. It
// carries the issuer binding and the (issuer-epoch, rotation-version) tuple; it holds
// NO succession record of its own — it inherits the issuer's epoch (claims 20, 27).
type Leaf struct {
	LeafID          string
	IssuerID        string
	IssuerEpoch     uint64
	RotationVersion uint64
}

// IssuerPosture is a succession-managed issuer's current cryptographic posture,
// derived from its own succession chain.
type IssuerPosture struct {
	IssuerID  string
	Epoch     uint64
	Algorithm string
	PublicDER []byte
}

// PostureFromChain derives the issuer's current posture from its verified succession
// chain (genesis + records). It reuses ee/succession.VerifyChain, so a non-monotonic,
// mis-anchored, or badly-signed issuer chain is rejected exactly as for any identity
// (INV-2/INV-3 at issuer granularity).
func PostureFromChain(genesis succession.GenesisRecord, chain []succession.SuccessionRecord) (IssuerPosture, error) {
	if err := succession.VerifyChain(genesis, chain, 0); err != nil {
		return IssuerPosture{}, err
	}
	p := IssuerPosture{IssuerID: genesis.IdentityID, Epoch: genesis.Epoch, Algorithm: string(genesis.Algorithm), PublicDER: genesis.PublicKey}
	if n := len(chain); n > 0 {
		head := chain[n-1]
		p.Epoch = head.Fields.Epoch
		p.Algorithm = string(head.Fields.SuccessorAlg)
		p.PublicDER = head.Fields.SuccessorPub
	}
	return p, nil
}

// IssueLeaf issues one leaf under the issuer's CURRENT posture: the leaf inherits the
// issuer's epoch and carries the (issuer-epoch, rotation-version) tuple. No per-leaf
// succession record is created.
func IssueLeaf(posture IssuerPosture, leafID string, rotationVersion uint64) Leaf {
	return Leaf{
		LeafID:          leafID,
		IssuerID:        posture.IssuerID,
		IssuerEpoch:     posture.Epoch,
		RotationVersion: rotationVersion,
	}
}

// ReissueFleet re-issues a whole fleet under the issuer's current posture. The fleet
// migrates to the issuer's algorithm-epoch by inheritance; the function produces zero
// succession records (claim 20) — only leaves carrying the issuer tuple.
func ReissueFleet(posture IssuerPosture, leafIDs []string) []Leaf {
	out := make([]Leaf, 0, len(leafIDs))
	for _, id := range leafIDs {
		// Ordinary re-issuance bumps the leaf's algorithm-invariant rotation version;
		// the algorithm migration is carried entirely by the inherited issuer epoch.
		out = append(out, IssueLeaf(posture, id, 1))
	}
	return out
}

// Tuple returns the leaf's (issuer-epoch, rotation-version) tuple (claim 27).
func (l Leaf) Tuple() (issuerEpoch, rotationVersion uint64) {
	return l.IssuerEpoch, l.RotationVersion
}

// EffectiveEpoch returns a leaf's effective algorithm-epoch: the issuer epoch it
// carries, validated against the issuer's posture. A leaf naming a different issuer,
// or claiming an epoch ahead of the issuer's current epoch, is rejected.
func EffectiveEpoch(leaf Leaf, posture IssuerPosture) (uint64, error) {
	if leaf.IssuerID != posture.IssuerID {
		return 0, fmt.Errorf("%w: %q != %q", ErrWrongIssuer, leaf.IssuerID, posture.IssuerID)
	}
	if leaf.IssuerEpoch > posture.Epoch {
		return 0, fmt.Errorf("%w: leaf %d > issuer %d", ErrLeafAheadOfIssuer, leaf.IssuerEpoch, posture.Epoch)
	}
	return leaf.IssuerEpoch, nil
}

// LeafPosture projects a leaf's effective algorithm + epoch from its issuer's chain
// (posture-projection extension). It derives the issuer posture, validates the leaf
// binding, and reports the issuer's algorithm at the leaf's epoch. Because a leaf
// inherits the issuer's posture, this is the issuer's current algorithm/epoch.
func LeafPosture(leaf Leaf, genesis succession.GenesisRecord, chain []succession.SuccessionRecord) (algorithm string, epoch uint64, err error) {
	posture, err := PostureFromChain(genesis, chain)
	if err != nil {
		return "", 0, err
	}
	e, err := EffectiveEpoch(leaf, posture)
	if err != nil {
		return "", 0, err
	}
	return posture.Algorithm, e, nil
}
