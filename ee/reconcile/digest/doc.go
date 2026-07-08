// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package digest implements the XREC state-digest layer: sorted Merkle leaves
// over XREC canonical records, inclusion and absence proofs, policy-posture
// counts, canonical state-digest bodies, and signer-side artifact signing.
//
// The package is signer-linkable: it imports no SQL, NATS, or HTTP server
// package. Cryptographic operations route through internal/crypto, preserving
// the AN-3 boundary.
package digest
