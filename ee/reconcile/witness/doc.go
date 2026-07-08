// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package witness builds XREC minimal divergence witnesses from two signed state
// digests and their local Merkle trees. It discloses only diverging canonical
// records, redacts bracketing non-diverging record bodies from absence proofs,
// and signs witness artifacts through the isolated signer process.
package witness
