# AGENTS.md — ee/reconcile/verify

This package is the proprietary XREC offline witness verifier. Every source file
must carry `SPDX-License-Identifier: LicenseRef-trstctl-EE`.

The verifier consumes already-signed digests and witness evidence, verifies them
with caller-supplied keys, and returns verifier-side determinations. It must not
generate canonical records, build digests, create witnesses, open network
connections, read/write stores, append ledger events, call the signing service, or
mutate control-plane state.

Keep all cryptographic checks behind `internal/crypto` and the existing
`ee/reconcile/digest` and `ee/reconcile/witness` verification APIs. Do not import
Go `crypto/*` packages directly here.
