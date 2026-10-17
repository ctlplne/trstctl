// SPDX-License-Identifier: BUSL-1.1

package succession_test

import (
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/succession"
)

func TestRecoveryEventIDsAreStableTenantScopedAndDistinct(t *testing.T) {
	for name, fn := range map[string]func(string, string, uint64) string{
		"successor": succession.RecoverySuccessorEventID,
		"record":    succession.RecoveryRecordEventID,
		"proof":     succession.RecoveryProofEventID,
	} {
		t.Run(name, func(t *testing.T) {
			id := fn("tenant-a", "identity", 1)
			parsed, err := uuid.Parse(id)
			if err != nil || parsed.Version() != 8 {
				t.Fatalf("event ID is not a deterministic UUIDv8: %q: %v", id, err)
			}
			if fn("tenant-a", "identity", 1) != id || fn("tenant-b", "identity", 1) == id ||
				fn("tenant-a", "other", 1) == id || fn("tenant-a", "identity", 2) == id {
				t.Fatal("event ID does not bind tenant, identity and epoch")
			}
		})
	}
	if succession.RecoverySuccessorEventID("t", "i", 1) == succession.RecoveryRecordEventID("t", "i", 1) ||
		succession.RecoveryRecordEventID("t", "i", 1) == succession.RecoveryProofEventID("t", "i", 1) {
		t.Fatal("recovery event classes do not have independent domains")
	}
}
