// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"

	"trstctl.com/trstctl/internal/store"
)

// Canary-first rollout: stop the fleet when the first batch does not serve
// (epic D6).
//
// A fleet re-issuance touches every certificate an issuer signed. Before
// verification existed there was nothing to gate on — the run could tell that
// deploys had been queued, not that any endpoint was serving the result — so a
// bad replacement propagated to the whole estate at the speed of the outbox.
//
// Now there is evidence. The first batch is the canary: if its replacements are
// verified serving, the rest proceeds; if any of them is not, the remainder
// halts. That is the whole mechanism, and its value depends entirely on two
// distinctions the vocabulary already makes.
//
// HALTED IS NOT FAILED. A halted batch was never attempted. Nothing in it
// changed and nothing in it is broken, so an operator must not be sent to
// investigate targets that are still serving perfectly well — during an
// incident, which is the worst possible time to waste attention.
//
// UNVERIFIED IS NOT VERIFIED. A canary nobody has probed yet does not authorise
// the rest of the fleet. The run waits rather than proceeding on silence,
// because "we have not looked" and "it is fine" are the two things this whole
// workstream exists to keep apart.

// canaryOutcome is what the canary batch says about proceeding.
type canaryOutcome int

const (
	// canaryPending: the canary has not been verified yet. The rest waits.
	canaryPending canaryOutcome = iota
	// canaryHealthy: every canary replacement is verified serving. Proceed.
	canaryHealthy
	// canaryFailed: at least one canary replacement is not being served. Halt.
	canaryFailed
)

// evaluateCanary reports what the first batch's verification says.
//
// Only the FIRST batch is the canary. Treating every batch as a gate for the
// next would serialise the whole rollout behind a verification interval each
// time, which turns a fleet re-issuance during an incident into an overnight
// job — the opposite of what an incident needs.
func evaluateCanary(ctx context.Context, st *store.Store, tenantID string, batches []store.FleetReissuanceBatch) canaryOutcome {
	if st == nil || len(batches) == 0 {
		return canaryPending
	}
	canary := batches[0]
	if len(canary.ReplacementIdentityIDs) == 0 {
		return canaryPending
	}
	outcome, err := st.SummarizeFleetVerification(ctx, tenantID, canary.ReplacementIdentityIDs)
	if err != nil {
		// A read failure is not a verdict. Treating it as healthy would let an
		// unreadable canary authorise the fleet; treating it as failed would
		// halt a rollout over a transient database error. Pending is the only
		// honest answer, and the next read resolves it.
		return canaryPending
	}
	switch {
	case outcome.Failed > 0:
		return canaryFailed
	case outcome.Unverified > 0 || outcome.Verified == 0:
		return canaryPending
	default:
		return canaryHealthy
	}
}
