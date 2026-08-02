// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package witness builds XREC minimal divergence witnesses from two signed state
// digests and their local Merkle trees. It discloses only diverging canonical
// records, redacts bracketing non-diverging record bodies from absence proofs,
// and signs witness artifacts through the isolated signer process.
//
// The package carries the divergence-class vocabulary (XREC-claim-2), the
// minimal-disclosure witness and its redacted absence proofs (XREC-claim-9),
// mutual countersignature (XREC-claims-6, 21), three-way majority
// classification (XREC-claim-7), the self-contained storable evidence body
// (XREC-claim-15), and the witness ledger vocabulary (XREC-claim-19).
package witness
