<!-- SPDX-License-Identifier: LicenseRef-trstctl-EE -->

# PCAS succession — conformance suite (r11)

This document *describes* the published Proof-Carrying Algorithm Succession (PCAS)
conformance suite for external relying parties. PCAS itself is a proprietary
Enterprise feature (`ee/`, `LicenseRef-trstctl-EE`); this document implements nothing.

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

## Edition boundary (G6)

`TestEdition_CoreBuildLinksNoPCAS` pins that the core-only (`trstctl_core`) build links
zero `ee/` packages, and `TestEdition_AllPCASPackagesAreEE` that every PCAS source file
is under `ee/` and carries the `LicenseRef-trstctl-EE` SPDX header — the same guarantee
as `make editions-gate`, asserted as tests. No MPL patent grant attaches to the
relying-party verifier (HARNESS §1.6 decision, 2026-07-05).

## End-to-end (claim 1)

`TestE2E_Succession_OfflineVerify` mints a multi-epoch algorithm succession for a
workload identity through the signer (each successor generated and used inside the
custody boundary, epochs enforced by the signer floor), assembles the trust-root-
anchored chain, and verifies it offline via `internal/rpverify` — the full method of
independent claim 1.
