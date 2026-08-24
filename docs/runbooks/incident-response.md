# Runbook: incident response

This runbook is for the credential-security incidents a private CA must be ready
for: a compromised or suspected-compromised key, an unexpected certificate, or a
credential leak. It assumes you operate trstctl per the other runbooks
([backup/DR](../disaster-recovery.md), [migrations](../migrations.md),
[key ceremony](key-ceremony.md)).

> **Maturity note.** The served binary publishes tenant-scoped OCSP/CRL status,
> serves root/intermediate CA creation and cross-signing through m-of-n ceremonies,
> answers blast-radius reads, monitors configured Certificate Transparency (CT)
> sources with outbox-backed alerts, and coordinates exact-H1 fleet reissuance.
> trstctl cannot install trust or replacement credentials on a target with no
> configured connector or enrolled agent. This runbook names those operator-owned
> boundaries instead of claiming the software completed them.

## First moves (any incident)

1. **Declare and timestamp** the incident; assign an incident lead.
2. **Capture safe diagnostics before restart.** Run
   `trstctl support-bundle --output incident-support.tar.gz --log-file <control-plane-log>`.
   This command does not need the HTTP server to be healthy. It records only build
   and configuration posture, categorical PostgreSQL/NATS/signer health, migration
   state, aggregate outbox/bulkhead counts, and a bounded log tail. It excludes raw
   environment/configuration values and fails closed if secret-, tenant-, or
   PII-shaped data remains after redaction.
3. **Preserve evidence.** Take a full DR artifact
   (`trstctl --full-backup-dir=<incident-backup-dir>`) before making changes. The
   event log inside it is the immutable source of truth and forensic record;
   the PostgreSQL-state stream keeps auth, CA, approval, secret, policy, and outbox
   state recoverable too.
4. **Verify the audit chain.** trstctl's audit trail is a hash-linked, signed chain
   (R2.1). Export the incident window, pin the public audit key and timestamp-authority
   root from a separate trusted channel, then run `trstctl-cli audit verify` as
   described in [Verify audit exports offline](../cli.md#verify-audit-exports-offline).
   The command recomputes the chain and rejects an invalid signature, timestamp, or
   anchor delay. This establishes a checkable timeline; every event records its actor.
5. **Scope the blast radius.** Identify the affected credentials and everything that
   depends on them with the served graph API (`/api/v1/graph/blast-radius/{id}`) or
   the `trstctl-cli graph blast-radius` command.

## Scenario: signer / CA key compromise

The issuing CA key lives in the out-of-process signer, isolated from the API
process; its compromise is the worst case.

1. **Contain.** Stop the signer to halt new issuance (issuance fails closed without
   it). Isolate the host.
2. **Assess.** Use the audit chain to determine what was issued during the exposure
   window.
3. **Rotate the CA** via an m-of-n [key ceremony](key-ceremony.md) — provision a new
   signer-backed successor CA; do not reuse the compromised key. The signer
   **persists and seals its CA key and preserves it across restarts** (R3.2), so
   rotation is a **deliberate re-key**, not an automatic restart side-effect. Once
   the successor authority exists, activate zero-downtime overlap with
   `POST /api/v1/ca/authorities/{predecessor-id}/rotate` and a `successor_id`.
   For same-lane signer-backed CA renewal, use
   `POST /api/v1/ca/authorities/{predecessor-id}/rekey` after a `rotation:<ca-id>`
   ceremony to mint fresh CA material directly. In both cases the predecessor issue
   URL remains valid, but new certificates are signed by the successor.
4. **Revoke** suspect leaves through the served lifecycle path; OCSP answers change
   immediately and trusted revocation paths publish a fresh tenant CRL. If the CA
   itself is compromised, distribute a replacement CA bundle and re-issue under the
   new CA. Ceremony-gated rotation and cross-signing are served. Trust-store
   distribution remains operator-owned for any target without a configured
   connector or enrolled agent.
5. **Re-issue and redeploy** active credentials under the new CA. Use the exact-H1
   fleet workflow at `POST /api/v1/incidents/fleet-reissuance-runs` (or
   `trstctl-cli incidents fleet-reissuance start`) so pause, resume, rollback, and
   signed evidence stay attached to the incident. Verify each target after delivery.
6. **Recover** any lost state from backup ([DR runbook](../disaster-recovery.md)).

## Scenario: unexpected certificate (mis-issuance)

1. trstctl's **Certificate Transparency monitoring** watches domains configured on
   a Discovery `ct_log` source and raises an outbox-backed alert for unrecognized
   issuance. Confirm the source checkpoint is current and the Alert Center shows a
   successful delivery; no configured source means no monitoring claim.
2. Confirm whether the certificate is yours (check inventory) or truly unexpected.
3. If unexpected and for your domain, treat it as a CA-trust incident: revoke,
   rotate if your CA issued it in error, and notify per policy.

## Scenario: leaked leaf credential or key

1. **Revoke** the affected certificate and **rotate** the credential (issue a
   replacement, deploy it, retire the old one on the lifecycle state machine).
2. **Audit** for misuse during the exposure window using the audit chain.
3. **Rotate any shared secrets** the credential could reach (use blast-radius scope).

## Communications & closeout

- Notify affected owners and relying parties per your
  [private disclosure policy](../security/reporting.md).
- Capture a timeline from the audit chain; write a post-incident review with
  concrete follow-ups (shorter validity, tighter custody, added monitoring).
- Confirm `/readyz` is green and the inventory is consistent before closing.

## Quick reference

| Lever | Where | Served today? |
| --- | --- | --- |
| Stop new issuance | stop the signer (fails closed) | yes |
| Verify audit timeline | `trstctl-cli audit verify` with separately pinned audit JWK and TSA root | yes |
| Backup / restore | `trstctl --full-backup-dir` / `--full-restore-dir` | yes |
| Rotate or re-key the CA | m-of-n [key ceremony](key-ceremony.md) plus `POST /api/v1/ca/authorities/{id}/rotate` or `/rekey` | yes |
| Revoke leaves (CRL/OCSP) | served revocation surface (`/ocsp/{tenant}`, `/crl/{tenant}`) | yes |
| Unexpected-issuance alert | CT monitoring | yes |
