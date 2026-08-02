// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package reducers maps read-only authority inventory snapshots into XREC
// canonical observed records. It holds only EE adapter logic: canonicalization
// remains in ee/reconcile/canon, while capability gating consumes the generic
// pluginhost grant model used by the free connector substrate.
//
// Reducers observe foreign authorities read-only and never mutate them
// (XREC-claim-8), across heterogeneous authority types — KMS, vault, CA,
// workload identity, and KMIP — behind one reducer contract (XREC-claim-17).
package reducers
