# AGENTS.md - ee/reconcile/canon/reducers/kmip

This package is proprietary XREC material under `LicenseRef-trstctl-EE`.

Rules:

- Keep every source file under this package tagged with `SPDX-License-Identifier: LicenseRef-trstctl-EE`.
- Keep `internal/kmip` empty. XREC KMIP observation lives here, under `ee/reconcile/canon/reducers/kmip`.
- Reuse the served EE KMIP bounded TTLV parser; do not add a second independent TTLV parser.
- Observation is read-only: Locate and Get-Attributes only. Create, Register, Revoke, Destroy, Activate, and key-material Get are outside this package.
- Do not fetch or persist KMIP key material or secret object values. Canonical evidence may contain only identifiers, public parameters, state, dates, and metadata.
