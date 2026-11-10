// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"testing"

	"trstctl.com/trstctl/internal/reconcile/canon"
)

// KMIP-O1: every KMIP object state reduces to a status canon knows. Pre-Active
// mapped to "pending", which canon does not have, so a key created and not
// yet activated read as "unknown" and every reconciliation round reported it
// as drift. A Pre-Active object may not be used for any cryptographic purpose
// until activated (KMIP 1.4, section 3.22): canon's disabled.
func TestEveryKMIPStateReducesToACanonStatusKMIPO1(t *testing.T) {
	want := map[State]string{
		StatePreActive:                    canon.StatusDisabled,
		StateActive:                       canon.StatusActive,
		StateDeactivated:                  canon.StatusDisabled,
		StateCompromised:                  canon.StatusRevoked,
		StateDestroyed:                    canon.StatusPendingDeletion,
		State("Destroyed Compromised"):    canon.StatusPendingDeletion,
		State("pre_active"):               canon.StatusDisabled,
		State("something a server added"): canon.StatusUnknown,
	}
	for state, status := range want {
		if got := statusID(state); got != status {
			t.Errorf("KMIP state %q reduces to %q, want %q", state, got, status)
		}
	}
	// Through canon itself: the reduced record keeps the status.
	obj := ManagedObject{UniqueIdentifier: "key-1", ObjectType: "PrivateKey", State: StatePreActive,
		Algorithm: "RSA", LengthBits: 2048, SPKI: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}
	record := keyObserved("kmip-authority", "tenant-a", obj)
	set, err := canon.ReduceTenant(canon.SpecVersionV1, "tenant-a", []canon.ObservedRecord{record})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range set.Records {
		if r.Status != canon.StatusDisabled {
			t.Fatalf("a Pre-Active key reduced to %q, want %q", r.Status, canon.StatusDisabled)
		}
	}
}
