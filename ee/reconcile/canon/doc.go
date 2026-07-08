// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package canon implements the proprietary XREC canonicalization reference
// profile: deterministic, tenant-scoped reduction of observed credential state
// into no-secret canonical records.
//
// XREC is whole-estate credential state reconciliation only. It may consume
// read-only observation substrate, but it does not mutate foreign planes and it
// does not implement PCAS succession-chain, bridge-record, or monotone-epoch
// semantics.
//
// This package owns R-1 through R-10 as code: record model, record keys, schema
// mapping, canonical JSON ordering, algorithm normalization, validity bucketing,
// value normalization, tenant scoping, secret exclusion, and determinism. R-11
// through R-19 are authored in SPEC.md for later XREC cards; this package does
// not build Merkle trees, sign digests, generate witnesses, schedule rounds, or
// call connectors.
package canon
