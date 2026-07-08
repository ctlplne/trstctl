// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package reducers maps read-only authority inventory snapshots into XREC
// canonical observed records. It holds only EE adapter logic: canonicalization
// remains in ee/reconcile/canon, while capability gating consumes the generic
// pluginhost grant model used by the free connector substrate.
package reducers
