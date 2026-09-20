// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/store"
)

// idempotencyResultProtectionReadout keeps state derivation in the composition
// root: the API sees only a tenant-scoped provider, while the store owns RLS and
// PostgreSQL catalog inspection.
func idempotencyResultProtectionReadout(
	st *store.Store,
	fleetReady bool,
) api.IdempotencyResultProtectionProvider {
	return func(ctx context.Context, tenantID string) (api.IdempotencyResultProtectionReadout, error) {
		status, err := st.IdempotencyResultProtectionStatus(ctx, tenantID)
		if err != nil {
			return api.IdempotencyResultProtectionReadout{}, err
		}
		floor, err := st.IdempotencyResultSealedFloorEnabled(ctx)
		if err != nil {
			return api.IdempotencyResultProtectionReadout{}, err
		}
		return deriveIdempotencyResultProtectionReadout(status, fleetReady, floor), nil
	}
}

func deriveIdempotencyResultProtectionReadout(
	status store.IdempotencyResultProtectionStatus,
	fleetReady, floor bool,
) api.IdempotencyResultProtectionReadout {
	out := api.IdempotencyResultProtectionReadout{
		FleetReady: fleetReady, SealedOnlyFloor: floor,
		RawV0Remaining:         status.RawV0,
		LegacyDynamicRemaining: status.LegacyDynamicLease,
		SealedResults:          status.SealedRowV1,
		PendingResults:         status.Pending,
		IndeterminateResults:   status.Indeterminate,
	}
	switch {
	case status.RemainingLegacy() > 0:
		out.State = "partial"
		out.Failure = "Legacy plaintext-compatible result codecs remain for this tenant."
		out.Recovery = "Stop old writers and restart an upgraded control-plane node to resume the RLS-scoped migration; do not assert fleet readiness yet."
	case fleetReady && !floor:
		out.State = "failed"
		out.Failure = "Fleet readiness is asserted but the sealed-only database floor is absent."
		out.Recovery = "Keep mutations unavailable, inspect the startup migration failure, and restart after PostgreSQL can validate the sealed-only floor."
	case status.Indeterminate > 0:
		out.State = "recovery_required"
		out.Failure = "One or more completed effects need explicit idempotency reconciliation."
		out.Recovery = "Reconcile each indeterminate claim before retrying its mutation; never mint or rotate blindly."
	case floor:
		out.State = "complete"
		out.Recovery = "No action is required; completed results are sealed and PostgreSQL rejects legacy write formats."
	case status.SealedRowV1 == 0 && status.Pending == 0:
		out.State = "empty"
		out.Recovery = "After every control-plane node is upgraded, assert fleet readiness to install the permanent sealed-only database floor."
	default:
		out.State = "ready_for_ratchet"
		out.Recovery = "After every control-plane node is upgraded, assert fleet readiness to install the permanent sealed-only database floor."
	}
	return out
}
