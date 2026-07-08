<!-- SPDX-License-Identifier: LicenseRef-trstctl-EE -->

# AGENTS.md - ee/reconcile/plan

This package owns XREC remediation plans and the signer-side operation gate for
the witness-to-plan chain. Keep every XREC-specific mechanism here; core may see
only the neutral `internal/signing` operation-gate seam.

- Do not import `crypto/*`; use `internal/crypto`.
- Do not import SQL, NATS, HTTP servers, stores, or connector code. This package
  is linked into `cmd/trstctl-signer`, so it must stay AN-4-small.
- Inputs are public evidence only: signed plans, recorded witness evidence,
  countersignatures, record keys, hashes, and operation names.
- The gate must fail closed. A missing trusted key, broken witness hash link,
  closed witness, missing required countersignature, or operation/class mismatch
  returns a signed refusal instead of approval.
