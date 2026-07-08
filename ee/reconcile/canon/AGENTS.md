# AGENTS.md - ee/reconcile/canon

This package is proprietary XREC material under `LicenseRef-trstctl-EE`.

Rules:

- Keep every source file under this package tagged with `SPDX-License-Identifier: LicenseRef-trstctl-EE`.
- This package implements only XREC R-1..R-10 canonical reduction. Do not add Merkle trees, digest signing, witness generation, rounds, quarantine, or remediation here.
- Hashing must route through `internal/crypto`; do not import `crypto/*`.
- Canonical records and digest inputs must never contain private keys, token values, passwords, API keys, or secret values. Secret references and provider-computed version/hash identifiers are allowed.
- Do not import or touch PCAS succession-chain bridge semantics. XREC canonicalizes whole-estate credential state only.
