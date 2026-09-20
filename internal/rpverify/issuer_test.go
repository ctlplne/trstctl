// SPDX-License-Identifier: BUSL-1.1

package rpverify_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/rpverify"
)

// memEpochStore is an in-memory EpochStore keyed by identity/authority.
type memEpochStore struct{ m map[string]uint64 }

func newMemEpochStore() *memEpochStore { return &memEpochStore{m: map[string]uint64{}} }

func (s *memEpochStore) LastAccepted(id string) (uint64, bool, error) {
	e, ok := s.m[id]
	return e, ok, nil
}
func (s *memEpochStore) SetLastAccepted(id string, epoch uint64) error {
	s.m[id] = epoch
	return nil
}

// TestRPVerify_RejectsLowerIssuerEpoch: the RP rejects a leaf whose carried issuer
// epoch is below the last-accepted issuer epoch for that authority, and advances the
// store on a current-or-newer epoch; tallies are per authority (PCAS-claim-27).
func TestRPVerify_RejectsLowerIssuerEpoch(t *testing.T) {
	store := newMemEpochStore()
	const authority = "spiffe://d/ca"

	// First acceptance establishes last-accepted = 3.
	if err := rpverify.AcceptLeafTuple(authority, rpverify.LeafTuple{IssuerEpoch: 3, RotationVersion: 1}, store); err != nil {
		t.Fatalf("initial accept: %v", err)
	}
	// A leaf carrying a lower issuer epoch is rejected.
	if err := rpverify.AcceptLeafTuple(authority, rpverify.LeafTuple{IssuerEpoch: 2, RotationVersion: 9}, store); !errors.Is(err, rpverify.ErrStaleIssuerEpoch) {
		t.Fatalf("stale issuer epoch: got %v, want ErrStaleIssuerEpoch", err)
	}
	// The same (current) epoch is accepted.
	if err := rpverify.AcceptLeafTuple(authority, rpverify.LeafTuple{IssuerEpoch: 3, RotationVersion: 2}, store); err != nil {
		t.Fatalf("current epoch rejected: %v", err)
	}
	// A newer epoch is accepted and advances last-accepted.
	if err := rpverify.AcceptLeafTuple(authority, rpverify.LeafTuple{IssuerEpoch: 4, RotationVersion: 1}, store); err != nil {
		t.Fatalf("newer epoch rejected: %v", err)
	}
	if err := rpverify.AcceptLeafTuple(authority, rpverify.LeafTuple{IssuerEpoch: 3}, store); !errors.Is(err, rpverify.ErrStaleIssuerEpoch) {
		t.Fatalf("after advance to 4, epoch 3 should be stale: got %v", err)
	}

	// A different authority is tracked independently (per-authority tallies).
	if err := rpverify.AcceptLeafTuple("spiffe://d/other-ca", rpverify.LeafTuple{IssuerEpoch: 1}, store); err != nil {
		t.Fatalf("independent authority epoch 1 rejected: %v", err)
	}
}
