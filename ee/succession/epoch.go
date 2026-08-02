// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import "trstctl.com/trstctl/internal/crypto"

// AlgorithmEpoch is the per-identity algorithm-epoch: a monotonically increasing
// counter that increments ONLY when the bound registry algorithm identifier of
// the identity changes. It is deliberately distinct from — and independent of —
// the core byok rotation-version (internal/crypto/byok.ManagedSigner.Version),
// which counts same-algorithm re-keys. A same-algorithm re-key advances the
// rotation-version but NOT the algorithm-epoch and is definitionally not a
// succession (PCAS-claim-22 / INV-2). Genesis is epoch 0.
//
// This type is the algorithm-epoch limb of the independent method claim
// (PCAS-claim-1): a monotonically increasing algorithm-epoch value, distinct
// from any rotation-version counter of the identity, incrementing only upon a
// change of cryptographic algorithm. Identity below carries the other half of
// that limb, the stable identity identifier invariant across such changes.
type AlgorithmEpoch uint64

// RotationCounter is the read-only view of core byok lifecycle state that the
// algorithm-epoch model layers beside. *internal/crypto/byok.ManagedSigner
// satisfies it (Version + Algorithm). PCAS reads this state and never mutates
// byok (AN-9: no PCAS scaffolding in, or mutation of, MPL core).
type RotationCounter interface {
	// Version is the same-algorithm rotation count from core byok.
	Version() int
	// Algorithm is the currently bound registry algorithm identifier.
	Algorithm() crypto.Algorithm
}

// Identity is the algorithm-succession state of one non-human identity: its
// current bound registry algorithm identifier, its current algorithm-epoch, and
// the current public key (DER). It holds NO private key material — only a public
// DER encoding and, on transitions, an opaque succession proof. Private keys
// live only in the isolated signer (AN-4), never here.
type Identity struct {
	id       string
	tenantID string
	epoch    AlgorithmEpoch
	alg      crypto.Algorithm
	pubDER   []byte
}

// NewGenesis establishes an identity's chain at epoch 0 bound to alg/pubDER.
func NewGenesis(id, tenantID string, alg crypto.Algorithm, pubDER []byte) *Identity {
	return &Identity{id: id, tenantID: tenantID, epoch: 0, alg: alg, pubDER: cloneBytes(pubDER)}
}

// ID returns the stable identity identifier.
func (i *Identity) ID() string { return i.id }

// TenantID returns the identity's tenant scope (AN-1).
func (i *Identity) TenantID() string { return i.tenantID }

// Epoch returns the current algorithm-epoch.
func (i *Identity) Epoch() AlgorithmEpoch { return i.epoch }

// Algorithm returns the currently bound registry algorithm identifier.
func (i *Identity) Algorithm() crypto.Algorithm { return i.alg }

// Descriptor pairs the algorithm-epoch with the core byok rotation-version,
// making the two-counter model explicit (PCAS-claim-22 / INV-2). The epoch is owned
// here (it advances only on a cross-algorithm succession); the rotation-version
// is read from core byok and never modified by PCAS.
type Descriptor struct {
	Algorithm       crypto.Algorithm
	Epoch           AlgorithmEpoch
	RotationVersion int
}

// Describe returns the (algorithm, epoch, rotation-version) tuple for this
// identity, reading the rotation-version from the supplied core byok counter.
// It performs a read only; it never mutates the counter or core byok state.
func (i *Identity) Describe(rc RotationCounter) Descriptor {
	return Descriptor{Algorithm: i.alg, Epoch: i.epoch, RotationVersion: rc.Version()}
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
