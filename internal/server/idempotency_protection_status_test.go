// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"

	"trstctl.com/trstctl/internal/store"
)

func TestIdempotencyResultProtectionReadoutStatesAndRecovery(t *testing.T) {
	tests := []struct {
		name       string
		status     store.IdempotencyResultProtectionStatus
		fleetReady bool
		floor      bool
		want       string
		failure    bool
	}{
		{name: "empty", want: "empty"},
		{name: "partial migration", status: store.IdempotencyResultProtectionStatus{RawV0: 1}, want: "partial", failure: true},
		{name: "ratchet ready", status: store.IdempotencyResultProtectionStatus{SealedRowV1: 3}, want: "ready_for_ratchet"},
		{name: "fleet mismatch", fleetReady: true, want: "failed", failure: true},
		{name: "reconciliation", status: store.IdempotencyResultProtectionStatus{SealedRowV1: 3, Indeterminate: 1}, want: "recovery_required", failure: true},
		{name: "complete", status: store.IdempotencyResultProtectionStatus{SealedRowV1: 3}, fleetReady: true, floor: true, want: "complete"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveIdempotencyResultProtectionReadout(tt.status, tt.fleetReady, tt.floor)
			if got.State != tt.want {
				t.Fatalf("state = %q, want %q: %+v", got.State, tt.want, got)
			}
			if (got.Failure != "") != tt.failure {
				t.Fatalf("failure presence = %t, want %t: %+v", got.Failure != "", tt.failure, got)
			}
			if got.Recovery == "" {
				t.Fatalf("state %q omitted recovery guidance", got.State)
			}
		})
	}
}
