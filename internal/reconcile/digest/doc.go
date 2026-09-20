// SPDX-License-Identifier: BUSL-1.1

// Package digest implements the XREC state-digest layer: sorted Merkle leaves
// over XREC canonical records, inclusion and absence proofs, policy-posture
// counts, canonical state-digest bodies, and signer-side artifact signing.
//
// The package is signer-linkable: it imports no SQL, NATS, or HTTP server
// package. Cryptographic operations route through internal/crypto, preserving
// the AN-3 boundary.
//
// Sorted Merkle leaves with inclusion and absence proofs are XREC-claim-9; the
// policy-posture summary carried in the signed digest body alongside the
// observation watermark is XREC-claim-11.
package digest
