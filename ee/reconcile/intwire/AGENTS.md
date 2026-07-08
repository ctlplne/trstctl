<!-- SPDX-License-Identifier: LicenseRef-trstctl-EE -->

# AGENTS.md - ee/reconcile/intwire

This package owns XREC's real-substrate integration gate. Tests here must use
real PostgreSQL/RLS, embedded file-backed NATS/JetStream, and the real
`cmd/trstctl-signer` process over UDS.

- Keep all files proprietary EE (`LicenseRef-trstctl-EE`).
- Do not import `crypto/*`; use `internal/crypto`.
- Do not replace the signer, event log, PostgreSQL store, or outbox with
  in-process doubles on the delivered path.
- Test-only connectors may record a corrective-write receipt, but authorization
  must come from the signer-side XREC operation gate.
