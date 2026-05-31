# Audit trail & compliance

certctl's audit trail is a **projection of the event log** (AN-2): every
state-changing operation is recorded as an immutable event, and the audit
query/export endpoints derive their views from that log. This page describes what
the audit subsystem **gives you** and — just as importantly — what it **does
not** do for you. certctl provides controls and evidence; **certification is yours
to obtain with your auditor**. Nothing here is a claim that deploying certctl
makes you compliant.

## What the audit subsystem provides

- **Completeness.** Every served mutation is recorded as an event (AN-2), so the
  trail reconstructs the full history of owners, issuers, identities, issuance,
  and revocation. The relational read model is a projection of the same events.
- **Attribution — who did what, when, under what authorization.** Each event
  carries the authenticated **actor** (subject and the role names it acted under),
  set from the verified principal (token or OIDC session, R1.2), plus the event
  time and tenant. A reconstructed trail answers "who revoked this credential, at
  what time, under which role."
- **Tamper-evidence.** Audit records are **hash-linked**: each record's hash folds
  in its predecessor's, so altering, dropping, inserting, or reordering any record
  changes that record's hash and every hash after it. The chain-verification
  routine detects it and names the first broken record.
- **Signed, offline-verifiable evidence export.** `GET /api/v1/audit/export`
  returns a compact JWS bundle (records + the chain head) signed with a
  **persistent** key, so a bundle exported today still verifies after a restart.
  An auditor verifies the signature and recomputes the chain offline.
- **Tenant isolation.** Every audit query is tenant-scoped (AN-1).

## The tamper-evidence trust model (read this)

The event log lives in NATS JetStream with **append-only file storage**. On top of
that, certctl maintains an application-level **hash chain** over the audit records
and publishes the chain head inside each **signed** export. The signed export is
the *anchor*: an export captured at time T attests to the exact records and head
at T, and any later alteration of the underlying log produces a different head
that no longer matches the trusted, signed bundle.

What this **does** detect: alteration, truncation, insertion, or reordering of
records relative to a previously signed bundle, and any in-place edit of a signed
bundle (the signature fails).

What it does **not** do by itself: provide continuous at-rest notarization without
a reference point. For that, an **operator** schedules periodic signed exports
(for example a nightly `certctl-cli audit export`) and retains them in
write-once / WORM storage; each export anchors the log up to its point in time. A
future hardware-anchored or external-notary checkpoint is a roadmap item.

## What the operator must still do

certctl enables the controls below; **you** operate them:

- **Custody and back up the export signing key** (`CERTCTL_AUDIT_SIGNING_KEY_FILE`,
  written `0600`). Losing it means past bundles still verify (you keep the public
  half) but you cannot produce new bundles under the same key; rotating it changes
  the verification key your auditor pins.
- **Distribute the verification (public) key** to auditors out of band.
- **Set and enforce a retention policy.** The event log is the source of truth and
  is **retained indefinitely by default** (certctl does not prune the spine —
  pruning would break projection rebuilds). `CERTCTL_AUDIT_RETENTION` documents
  your policy; long-term archival of signed bundles to WORM storage
  (`CERTCTL_AUDIT_ARCHIVE_DIR` or your own pipeline) is your responsibility.
- **Schedule periodic signed exports** to anchor the log over time (above).
- **Run the rest of the program**: access reviews, change management, incident
  response, vendor management, and the framework-specific evidence your auditor
  requires.

## Framework mapping — *enables* vs. operator responsibility

This maps the controls certctl's audit/identity subsystems **help satisfy**. It is
not an attestation; an assessor decides whether your overall program meets each
control.

| Framework | Controls certctl's audit trail helps with | Still the operator's |
| --- | --- | --- |
| SOC 2 | CC7.2/7.3 (security event logging), CC8.1 (change tracking) — *attributable, tamper-evident event trail + signed evidence* | Monitoring/alerting program, change-management process, retention enforcement, the audit engagement |
| ISO 27001 | A.8.15/8.16 (logging, monitoring), A.5.28 (evidence collection) — *event capture + exportable evidence* | Log review cadence, retention schedule, ISMS scope and operation |
| PCI DSS v4 | Req. 10 (log and monitor access) — *who/what/when trail*; 10.5 supported by retention config + archive | 10.5 retention **enforcement** (≥12 months, 3 readily available), daily review, FIM, key custody |
| HIPAA | §164.312(b) audit controls — *recording and examining activity* | §164.308 review procedures, retention (6 years), BAAs |
| FedRAMP / NIST 800-53 | AU-2/3 (event content), AU-9 (protection of audit info, via the chain + signed export), AU-12 (generation) | AU-6 review, AU-11 retention enforcement, AU-9 storage hardening (WORM), FIPS-validated crypto (a build caveat) |

**Defensible today:** an attributable, tamper-evident, event-sourced audit trail
with signed, offline-verifiable evidence export, and multi-tenant isolation.
**Explicitly not claimed:** that certctl is "compliant" or "certified" with any
framework, that FIPS-validated cryptography is in the default build, or that
retention is enforced for you.

See [Configuration → Audit](configuration.md#audit) for the settings referenced
here.
