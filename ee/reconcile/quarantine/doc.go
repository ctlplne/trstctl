// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package quarantine evaluates XREC divergence witnesses against a per-tenant
// containment policy, records quarantine-entered events, and exposes a generic
// admission hook that refuses only operations whose observed-state inputs depend
// on an open quarantined plane.
package quarantine
