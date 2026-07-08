# AGENTS.md — ee/reconcile/witness

This package implements XREC R-15 divergence witnesses only: minimal differing
record disclosure, inclusion proofs, bracketing absence proofs, four-class
classification, witness content hashing, and witness artifact signing.

Do not add round scheduling, ledger/countersign events, quarantine, remediation
plans, or the offline verifier here; those belong to later XREC cards.

All Go files in this package must carry
`SPDX-License-Identifier: LicenseRef-trstctl-EE`. Crypto must route through
`internal/crypto`; do not import Go `crypto/*` packages directly.
