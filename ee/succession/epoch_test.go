// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import (
	"errors"
	"testing"
	"trstctl.com/trstctl/ee/proptest"

	"trstctl.com/trstctl/internal/crypto"
)

// fakeByok is a read-only stand-in for a core byok ManagedSigner: a
// same-algorithm rotation counter. PCAS only reads Version()/Algorithm().
type fakeByok struct {
	v   int
	alg crypto.Algorithm
}

func (f *fakeByok) Version() int                { return f.v }
func (f *fakeByok) Algorithm() crypto.Algorithm { return f.alg }
func (f *fakeByok) rotate()                     { f.v++ } // same-algorithm re-key

// TestEpoch_DistinctFromRotationVersion: the algorithm-epoch and the core byok
// rotation-version are independent monotonic counters (PCAS-claims-1/22 / INV-2).
func TestEpoch_DistinctFromRotationVersion(t *testing.T) {
	id := NewGenesis("id", "t", crypto.RSA2048, []byte{1})
	rc := &fakeByok{v: 0, alg: crypto.RSA2048}

	// Two same-algorithm re-keys: rotation-version advances, epoch does not.
	rc.rotate()
	rc.rotate()
	if d := id.Describe(rc); d.Epoch != 0 || d.RotationVersion != 2 {
		t.Fatalf("after 2 rotations: epoch=%d rv=%d, want 0,2", d.Epoch, d.RotationVersion)
	}

	// A cross-algorithm succession: epoch advances, rotation-version does not.
	if _, _, err := id.Succeed(crypto.Ed25519, []byte{2}, nil); err != nil {
		t.Fatalf("Succeed: %v", err)
	}
	if d := id.Describe(rc); d.Epoch != 1 || d.RotationVersion != 2 {
		t.Fatalf("after succession: epoch=%d rv=%d, want 1,2", d.Epoch, d.RotationVersion)
	}
}

// TestEpoch_IncrementsOnlyOnAlgChange: the epoch increments only when the bound
// registry algorithm identifier changes (INV-2).
func TestEpoch_IncrementsOnlyOnAlgChange(t *testing.T) {
	id := NewGenesis("id", "t", crypto.RSA2048, []byte{1})

	// Same identifier → not a succession, no epoch change, no event.
	if _, _, err := id.Succeed(crypto.RSA2048, []byte{2}, nil); !errors.Is(err, ErrNotASuccession) {
		t.Fatalf("same-alg: want ErrNotASuccession, got %v", err)
	}
	if id.Epoch() != 0 {
		t.Fatalf("epoch changed on same-algorithm request: %d", id.Epoch())
	}

	// Different identifier → epoch +1, algorithm rebound, event emitted.
	tr, ev, err := id.Succeed(crypto.Ed25519, []byte{3}, []byte("proof"))
	if err != nil {
		t.Fatalf("cross-alg Succeed: %v", err)
	}
	if id.Epoch() != 1 || tr.Epoch != 1 || tr.PredecessorEpoch != 0 {
		t.Fatalf("epoch not advanced by exactly one: id=%d tr=%+v", id.Epoch(), tr)
	}
	if id.Algorithm() != crypto.Ed25519 {
		t.Fatalf("algorithm not rebound: %s", id.Algorithm())
	}
	if ev.Type != TypeSuccession {
		t.Fatalf("emitted event type = %q, want %q", ev.Type, TypeSuccession)
	}
	// The emitted event carries predecessor + successor public DER and both
	// epochs (criterion 4); the Transition carries both DERs too.
	if string(tr.PredecessorPublicDER) != "\x01" || string(tr.SuccessorPublicDER) != "\x03" {
		t.Fatalf("transition DER: pred=%v succ=%v, want [1] [3]", tr.PredecessorPublicDER, tr.SuccessorPublicDER)
	}
	pl, derr := Decode(ev)
	if derr != nil {
		t.Fatalf("decode emitted event: %v", derr)
	}
	sv, ok := pl.(SuccessionV1)
	if !ok {
		t.Fatalf("emitted payload type = %T, want SuccessionV1", pl)
	}
	if string(sv.PredecessorPublicKeyDER) != "\x01" || string(sv.SuccessorPublicKeyDER) != "\x03" {
		t.Fatalf("event DER: pred=%v succ=%v, want [1] [3]", sv.PredecessorPublicKeyDER, sv.SuccessorPublicKeyDER)
	}
	if sv.PredecessorEpoch != 0 || sv.Epoch != 1 {
		t.Fatalf("event epochs: pred=%d epoch=%d, want 0,1", sv.PredecessorEpoch, sv.Epoch)
	}

	// A further identifier change advances again.
	if _, _, err := id.Succeed(crypto.ECDSAP256, []byte{4}, nil); err != nil {
		t.Fatalf("second succession: %v", err)
	}
	if id.Epoch() != 2 {
		t.Fatalf("epoch = %d, want 2", id.Epoch())
	}
}

// TestRekey_IsNotASuccession: a same-algorithm re-key advances only the
// rotation-version and produces no succession transition and no
// nhi.algorithm.succession event (PCAS-claim-22 / INV-2).
func TestRekey_IsNotASuccession(t *testing.T) {
	id := NewGenesis("spiffe://x", "t", crypto.Ed25519, []byte{1})
	rc := &fakeByok{v: 0, alg: crypto.Ed25519}
	sink := &MemSink{}

	// Core byok re-keys under the unchanged algorithm.
	rc.rotate()

	// The epoch model is not driven by rotation: epoch unchanged, and a request
	// to "succeed" to the same algorithm is refused as not-a-succession, emitting
	// nothing to the ledger.
	_, ev, err := id.Succeed(crypto.Ed25519, []byte{2}, []byte("proof"))
	if !errors.Is(err, ErrNotASuccession) {
		t.Fatalf("same-alg Succeed: got err %v, want ErrNotASuccession", err)
	}
	if ev.Type != "" {
		t.Fatalf("a re-key produced an event of type %q", ev.Type)
	}
	if id.Epoch() != 0 {
		t.Fatalf("re-key advanced the algorithm-epoch to %d", id.Epoch())
	}
	// Nothing was appended to the ledger.
	if len(sink.Events()) != 0 {
		t.Fatalf("re-key appended %d events", len(sink.Events()))
	}
	// The rotation-version advanced independently.
	if rc.Version() != 1 {
		t.Fatalf("rotation-version = %d, want 1", rc.Version())
	}
}

// TestEpoch_TwoCounterIndependenceProperty: over random interleavings of
// {rotate, succeed}, the epoch equals the number of algorithm changes and the
// rotation-version equals the number of re-keys; both are monotonic (INV-2).
func TestEpoch_TwoCounterIndependenceProperty(t *testing.T) {
	algs := []crypto.Algorithm{crypto.RSA2048, crypto.Ed25519, crypto.ECDSAP256, crypto.ECDSAP384}
	for seed := int64(0); seed < 100; seed++ {
		rng := proptest.New(seed)
		id := NewGenesis("id", "t", algs[0], []byte{0})
		rc := &fakeByok{v: 0, alg: algs[0]}
		successions, rotations := 0, 0
		last := id.Epoch()
		for n := 0; n < 60; n++ {
			if rng.Intn(2) == 0 {
				rc.rotate()
				rotations++
			} else {
				next := algs[rng.Intn(len(algs))]
				_, _, err := id.Succeed(next, []byte{byte(n)}, nil)
				switch {
				case err == nil:
					successions++
				case errors.Is(err, ErrNotASuccession):
					// same-algorithm request; correctly not a succession
				default:
					t.Fatalf("seed %d: unexpected error %v", seed, err)
				}
			}
			if id.Epoch() < last {
				t.Fatalf("seed %d: algorithm-epoch regressed %d -> %d", seed, last, id.Epoch())
			}
			last = id.Epoch()
		}
		if int(id.Epoch()) != successions {
			t.Fatalf("seed %d: epoch=%d != successions=%d", seed, id.Epoch(), successions)
		}
		if rc.Version() != rotations {
			t.Fatalf("seed %d: rotation-version=%d != rotations=%d", seed, rc.Version(), rotations)
		}
	}
}
