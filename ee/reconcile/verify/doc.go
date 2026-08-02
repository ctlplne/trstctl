// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package verify implements the proprietary XREC offline witness verifier.
//
// It consumes already-signed state digests and a signed divergence witness,
// verifies signatures and Merkle proofs using caller-supplied verification keys,
// and returns the verified divergence determinations. It performs no reduction,
// digest generation, witness generation, network I/O, ledger I/O, or control-plane
// mutation.
//
// This is the independent-verifier embodiment (XREC-claim-20): it reaches
// neither authority, consuming only the self-contained stored witness
// (XREC-claim-15), optionally requiring a countersignature by verifier policy
// (XREC-claim-21) and rejecting evidence past its freshness bound
// (XREC-claim-22).
package verify
