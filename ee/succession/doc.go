// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package succession implements the proprietary (Enterprise/Provider) core of
// Proof-Carrying Algorithm Succession (PCAS): the append-only, per-identity
// cryptographic-succession lifecycle for non-human identities — the method of
// PCAS-claim-1 (stable identity identifier invariant across algorithm changes,
// a monotonically increasing algorithm-epoch distinct from rotation versions,
// and dual-signed succession records over a common commitment), whose limbs
// the files and subpackages below carry under their own claim citations.
//
// PCAS is a patent-pending feature set — certctl LLC filed a US
// provisional application covering it in July 2026 and nothing has issued —
// and it lives entirely under ee/ (SPDX LicenseRef-trstctl-EE); MPL core never
// imports it outside the tagged attach seam (AN-9, HARNESS §1.6). This package
// touches no core code.
//
// This file set (card PCAS-01) provides two things:
//
//   - the versioned AN-2 ledger event vocabulary for the algorithm lifecycle —
//     nhi.crypto.finding, nhi.algorithm.succession, nhi.algorithm.retirement,
//     and nhi.rp.ack — with round-trip encode/decode (events.go); and
//   - a deterministic per-identity crypto-posture projection folded from those
//     events and reconstructable by replay of the ledger (posture.go), which
//     enables PCAS-claim-10 and establishes INV-10 while preserving INV-4
//     (idempotent under at-least-once/duplicate delivery).
//
// Card PCAS-03 additionally provides the AlgorithmEpoch model (epoch.go,
// transition.go): a per-identity algorithm-epoch that is distinct from and
// independent of the core byok rotation-version, so a same-algorithm re-key is
// definitionally not a succession (PCAS-claim-22 / INV-2).
//
// Deliberately out of scope here (see the named cards): the dual-signed
// succession *record*, its commitment, and any cryptography (PCAS-04); the
// durable RLS serving copy of this projection (PCAS-02); minting inside the
// isolated signer (PCAS-05); and the signed posture *report* of PCAS-claim-50
// (PCAS-30). A succession event here carries only posture-relevant fields plus
// an opaque RecordDigest reference to the record that PCAS-04 will define.
package succession
