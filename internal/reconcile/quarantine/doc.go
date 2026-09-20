// SPDX-License-Identifier: BUSL-1.1

// Package quarantine evaluates XREC divergence witnesses against a per-tenant
// containment policy, records quarantine-entered events, and exposes a generic
// admission hook that refuses only operations whose observed-state inputs depend
// on an open quarantined plane.
//
// Quarantine entry driven by a recorded divergence witness is XREC-claim-4, and
// release only via a reconciliation-completion record is XREC-claim-5.
package quarantine
