<!-- SPDX-License-Identifier: LicenseRef-trstctl-EE -->

# AGENTS.md - ee/reconcile/quarantine

This package is Enterprise-only XREC containment code. Keep every mechanism here
under `ee/reconcile/quarantine`; core may expose only feature-neutral admission or
event seams and must not import this package.

Quarantine decisions are tenant-scoped, event-sourced records. A refusal must name
the tenant, the observed authority/provenance that caused denial, and the witness
that opened the quarantine when known. The hook performs no key operation.

Completion releases are also event records: verify regenerated digest inclusion
proofs over the witness's diverging keys before appending `xrec.reconciliation.completed`,
then release only the open quarantines tied to that witness. Operator overrides
must carry a justification reference and verify against a configured trusted
operator key before appending the release event.
