// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package verify implements the proprietary XREC offline witness verifier.
//
// It consumes already-signed state digests and a signed divergence witness,
// verifies signatures and Merkle proofs using caller-supplied verification keys,
// and returns the verified divergence determinations. It performs no reduction,
// digest generation, witness generation, network I/O, ledger I/O, or control-plane
// mutation.
package verify
