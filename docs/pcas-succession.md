<!-- SPDX-License-Identifier: BUSL-1.1 -->

# PCAS succession — conformance suite

This document *describes* the published Proof-Carrying Algorithm Succession (PCAS)
conformance suite for external relying parties. PCAS ships in the BUSL-1.1 core
under `internal/succession`, `internal/rpverify`, and `internal/translog`; it does
not require an Enterprise or Provider license.

## Published vectors

Versioned conformance vectors live under
`internal/succession/conformance/testdata/`. `chain_vector.json` (schema `version: 1`) is a
genesis-anchored succession chain of dual-signed records. A relying party is
conformant if it reproduces the PASS/FAIL verdicts of the reference verifier
(`internal/rpverify`) on every published vector.

Each vector carries the tenant-trust-root public key, the genesis record, the record
chain, and the expected head epoch. Verification is **offline**: no algorithm
negotiation, no runtime cryptographic-provider load, and no network fetch — the caller
supplies the chain (independent claim 13).

## Differential conformance

`TestConformance_ChainVector` verifies each vector with `internal/rpverify` **and** with an
independent re-implementation of chain verification (`differentialVerify`), and
requires the two to agree — on acceptance of a valid chain and on rejection of a
tampered one. An external re-implementation should agree likewise.

## Fuzz targets

`FuzzDecodeRecord`, `FuzzVerifyChain`, and `FuzzStapleDecode` exercise the record,
chain, and staple parsers; their seed corpora run under `go test` (and
`make fuzz-smoke`). No input may cause a panic.

## Edition boundary

`TestEdition_CoreBuildLinksPCASAndNoEE` checks that the core-only
(`trstctl_core`) build includes PCAS and links zero `ee/` packages.
`TestEdition_AllPCASPackagesAreCore` checks that the PCAS package trees live under
`internal/` and carry the `BUSL-1.1` SPDX header. `make editions-gate` checks the
build boundary. See [editions and licensing](editions.md) for the applicable terms.

## End-to-end (claim 1)

`TestE2E_Succession_OfflineVerify` mints a multi-epoch algorithm succession for a
workload identity through the signer (each successor generated and used inside the
custody boundary, epochs enforced by the signer floor), assembles the trust-root-
anchored chain, and verifies it offline via `internal/rpverify` — the full method of
independent claim 1.
