// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import (
	"errors"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

// ErrNotASuccession is returned by Succeed when the requested successor algorithm
// equals the current bound identifier: that is a same-algorithm re-key (a
// rotation-version bump in core byok), not a succession. It advances no
// algorithm-epoch and emits no nhi.algorithm.succession event (claim 22 / INV-2).
var ErrNotASuccession = errors.New("succession: same-algorithm re-key is not a succession")

// Transition is a first-class cross-algorithm succession transition for an
// identity. It carries public key material (DER) and an opaque SuccessionProof
// only; the dual-signed record, its canonical commitment, and all cryptography
// are PCAS-04 — SuccessionProof is produced by PCAS-04's encoder and carried
// opaquely here so this model stays free of crypto and of private key material.
type Transition struct {
	IdentityID           string
	TenantID             string
	PredecessorEpoch     AlgorithmEpoch
	Epoch                AlgorithmEpoch
	PredecessorAlgorithm crypto.Algorithm
	SuccessorAlgorithm   crypto.Algorithm
	PredecessorPublicDER []byte
	SuccessorPublicDER   []byte
	SuccessionProof      []byte // opaque encoded dual-signed record (PCAS-04)
}

// Succeed applies a cross-algorithm succession advancing the identity to
// successorAlg with the given successor public key (DER) and opaque proof. On a
// real algorithm change it increments the algorithm-epoch by exactly one,
// rebinds the identity to the new algorithm, and returns the Transition together
// with the nhi.algorithm.succession ledger event (PCAS-01) to append to the AN-2
// log. It returns ErrNotASuccession — advancing nothing and emitting nothing —
// when successorAlg equals the current bound identifier (claim 22 / INV-2).
func (i *Identity) Succeed(successorAlg crypto.Algorithm, successorPubDER, proof []byte) (Transition, eventspec.Event, error) {
	if successorAlg == i.alg {
		return Transition{}, eventspec.Event{}, ErrNotASuccession
	}
	t := Transition{
		IdentityID:           i.id,
		TenantID:             i.tenantID,
		PredecessorEpoch:     i.epoch,
		Epoch:                i.epoch + 1,
		PredecessorAlgorithm: i.alg,
		SuccessorAlgorithm:   successorAlg,
		PredecessorPublicDER: cloneBytes(i.pubDER),
		SuccessorPublicDER:   cloneBytes(successorPubDER),
		SuccessionProof:      cloneBytes(proof),
	}
	ev, err := Encode(SuccessionV1{
		IdentityID:              i.id,
		TenantID:                i.tenantID,
		PredecessorEpoch:        uint64(t.PredecessorEpoch),
		Epoch:                   uint64(t.Epoch),
		PredecessorAlgorithm:    string(i.alg),
		PredecessorPublicKeyDER: cloneBytes(i.pubDER),
		SuccessorAlgorithm:      string(successorAlg),
		SuccessorPublicKeyDER:   cloneBytes(successorPubDER),
		RecordDigest:            cloneBytes(proof),
	})
	if err != nil {
		return Transition{}, eventspec.Event{}, err
	}
	i.epoch++
	i.alg = successorAlg
	i.pubDER = cloneBytes(successorPubDER)
	return t, ev, nil
}
