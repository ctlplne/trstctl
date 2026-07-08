<!-- SPDX-License-Identifier: LicenseRef-trstctl-EE -->

# AGENTS.md - ee/reconcile/plan/remediation

This package is the control-plane side of XREC remediation authorization. It may
use PostgreSQL, the core store, and the core outbox because it is wired only into
`cmd/trstctl`, not `cmd/trstctl-signer`.

- Keep signer-linked plan verification in the parent package.
- Do not import `crypto/*`; use `internal/crypto`.
- Every table and query must stay tenant-scoped with RLS.
- External corrective writes must be staged through the core outbox. Do not call a
  connector from the authorization transaction.
