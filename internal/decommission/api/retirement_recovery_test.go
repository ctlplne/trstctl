// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"

	"trstctl.com/trstctl/internal/decommission/retirement"
)

func TestRetirementRecoveryActionBindsFailedDeliveryToFrozenEvidence(t *testing.T) {
	failed := retirement.DeliveryState{Status: "failed", Attempts: 10, AttemptLimit: 10}
	for _, tc := range []struct {
		name           string
		statePosition  uint64
		frozenPosition uint64
		status         string
		delivery       retirement.DeliveryState
		want           string
	}{
		{"unchanged failed command", 42, 42, retirement.StatusPending, failed, "retry_delivery"},
		{"new dependent evidence", 43, 42, retirement.StatusPending, failed, "fresh_command"},
		{"failed but retry grant remains", 42, 42, retirement.StatusPending, retirement.DeliveryState{Status: "failed", Attempts: 10, AttemptLimit: 11}, "none"},
		{"delivery in progress", 43, 42, retirement.StatusPending, retirement.DeliveryState{Status: "pending", Attempts: 10, AttemptLimit: 10}, "none"},
		{"terminal destruction", 43, 42, retirement.StatusDestroyed, failed, "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := retirementRecoveryAction(tc.statePosition, tc.frozenPosition, tc.status, tc.delivery)
			if got != tc.want {
				t.Fatalf("recovery action = %q, want %q", got, tc.want)
			}
		})
	}
}
