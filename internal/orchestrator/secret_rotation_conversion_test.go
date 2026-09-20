// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import "testing"

func TestStoredSecretRotationEventSequenceRejectsNonPositiveAuthority(t *testing.T) {
	for _, sequence := range []int64{-1, 0} {
		if got, err := storedSecretRotationEventSequence(sequence); err == nil || got != 0 {
			t.Fatalf("sequence %d = %d, %v; want zero plus conflict", sequence, got, err)
		}
	}
	if got, err := storedSecretRotationEventSequence(1); err != nil || got != 1 {
		t.Fatalf("sequence 1 = %d, %v", got, err)
	}
}
