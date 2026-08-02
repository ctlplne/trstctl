// SPDX-License-Identifier: LicenseRef-trstctl-EE

package signerwiring

import (
	"testing"

	"trstctl.com/trstctl/ee/succession/minter"
	"trstctl.com/trstctl/internal/crypto"
)

// ---- AN4-FLOORMONO: one monotonicity contract for every FloorStore -----------
//
// minter.FloorStore is the signer's per-identity algorithm-epoch floor: the
// anti-rollback state on which PCAS-claim-12's "refuse a succession at an epoch
// at or below the floor" refusal rests (INV-3). A floor that can fall lets a
// retired epoch be minted again.
//
// That property belongs to the INTERFACE, not to any one implementation, so this
// file is deliberately a SHARED contract test rather than a test per store: every
// FloorStore the signer can be wired with runs the same table. A store that
// quietly lowers the floor is caught no matter which one an operator's flags
// select, and a fifth implementation is one table row away from being covered
// instead of one omission away from repeating the divergence this guard closed.
//
// It lives in package signerwiring (not signerwiring_test) because
// interimFloorStore and newInterimFloorStore are unexported, and signerwiring is
// the only package that can see both them and the exported minter stores.

// floorStoreSubject names one FloorStore implementation under contract.
type floorStoreSubject struct {
	name  string
	store minter.FloorStore
}

// floorStoreSubjects returns a freshly constructed instance of every FloorStore
// the signer can be wired with. The interim store is first because it is the
// DEFAULT: NewProductionMinter selects it whenever Config.Floors is nil and
// Config.FloorDir is empty, i.e. any signer started without a custody directory.
func floorStoreSubjects(t *testing.T) []floorStoreSubject {
	t.Helper()
	durable, err := minter.NewDurableFloorStore(t.TempDir())
	if err != nil {
		t.Fatalf("AN4-FLOORMONO: construct minter.DurableFloorStore: %v", err)
	}
	return []floorStoreSubject{
		{"signerwiring_interimFloorStore", newInterimFloorStore()},
		{"minter_DurableFloorStore", durable},
		{"minter_HistoryFloorStore", minter.NewHistoryFloorStore()},
		{"minter_SoftHSM_FloorStore", minter.NewSoftHSM(crypto.NewSoftwareBackend()).FloorStore()},
	}
}

// wantFloor asserts the OBSERVABLE floor for id — what the minter reads back
// through Load. How a store represents the floor internally (an in-memory
// counter, an atomically-written file, a maximum derived over recorded history,
// module-resident sealed state) is its own business; what it reports must never
// go down.
func wantFloor(t *testing.T, s minter.FloorStore, id string, want uint64) {
	t.Helper()
	got, err := s.Load()
	if err != nil {
		t.Fatalf("AN4-FLOORMONO: Load: %v", err)
	}
	if got[id] != want {
		t.Fatalf("AN4-FLOORMONO: floor for %q is %d, want %d; Advance moved the epoch floor DOWN. The floor only ever rises - that is the anti-rollback state a stale-epoch succession refusal rests on (PCAS-claim-12 / INV-3), and whether it holds must not depend on which FloorStore happens to be wired", id, got[id], want)
	}
}

// TestFloorStoreContractAdvanceIsMonotonic holds every FloorStore to the same
// monotonicity contract: Advance raises the floor, and a lower, equal, or zero
// epoch is an idempotent no-op rather than a regression or an error. Idempotence
// matters as much as monotonicity here: Advance sits on the mint path, so a retry
// of a mint that already recorded its floor must succeed silently.
// ELI5: the epoch floor is a ratchet. Every implementation of the ratchet has to
// be a ratchet, including the one you get when you start the signer with no flags.
func TestFloorStoreContractAdvanceIsMonotonic(t *testing.T) {
	for _, subject := range floorStoreSubjects(t) {
		t.Run(subject.name, func(t *testing.T) {
			const id = "identity-monotonic"
			s := subject.store

			if err := s.Advance(id, 5); err != nil {
				t.Fatalf("AN4-FLOORMONO: initial Advance to 5: %v", err)
			}
			wantFloor(t, s, id, 5)

			if err := s.Advance(id, 3); err != nil {
				t.Fatalf("AN4-FLOORMONO: Advance to a LOWER epoch must be a silent no-op, not an error: %v", err)
			}
			wantFloor(t, s, id, 5)

			if err := s.Advance(id, 5); err != nil {
				t.Fatalf("AN4-FLOORMONO: re-Advance to the CURRENT epoch must be idempotent, not an error: %v", err)
			}
			wantFloor(t, s, id, 5)

			if err := s.Advance(id, 0); err != nil {
				t.Fatalf("AN4-FLOORMONO: Advance to the zero epoch must be a no-op, not an error: %v", err)
			}
			wantFloor(t, s, id, 5)

			if err := s.Advance(id, 6); err != nil {
				t.Fatalf("AN4-FLOORMONO: Advance to a HIGHER epoch must still raise the floor: %v", err)
			}
			wantFloor(t, s, id, 6)
		})
	}
}

// TestFloorStoreContractAdvanceIsPerIdentity holds every FloorStore to the second
// half of the contract: the floor is PER IDENTITY. One identity's succession must
// neither raise nor lower another's floor, or a busy identity would silently
// retire epochs belonging to a quiet one.
func TestFloorStoreContractAdvanceIsPerIdentity(t *testing.T) {
	for _, subject := range floorStoreSubjects(t) {
		t.Run(subject.name, func(t *testing.T) {
			s := subject.store

			if err := s.Advance("identity-a", 4); err != nil {
				t.Fatalf("AN4-FLOORMONO: Advance identity-a to 4: %v", err)
			}
			if err := s.Advance("identity-b", 2); err != nil {
				t.Fatalf("AN4-FLOORMONO: Advance identity-b to 2: %v", err)
			}
			wantFloor(t, s, "identity-a", 4)
			wantFloor(t, s, "identity-b", 2)

			if err := s.Advance("identity-b", 1); err != nil {
				t.Fatalf("AN4-FLOORMONO: lower Advance on identity-b: %v", err)
			}
			wantFloor(t, s, "identity-a", 4)
			wantFloor(t, s, "identity-b", 2)
		})
	}
}
