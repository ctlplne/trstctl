# Runbook: incident response

This runbook is for the credential-security incidents a private CA must be ready
for: a compromised or suspected-compromised key, an unexpected certificate, or a
credential leak. It assumes you operate trstctl per the other runbooks
([backup/DR](../disaster-recovery.md), [migrations](../migrations.md),
[key ceremony](key-ceremony.md)).

> **Maturity note.** The served binary now publishes tenant-scoped OCSP/CRL status
> for issued leaves and the credential graph can answer blast-radius reads. Some
> response capabilities remain library/operator work — notably CA hierarchy
> rotation ceremonies, CT alert scheduling, and connector-driven redeploys. Where a
> step depends on an as-yet-unserved subsystem, this runbook says so and gives the
> operational alternative.

## First moves (any incident)

1. **Declare and timestamp** the incident; assign an incident lead.
2. **Preserve evidence.** Take a full DR artifact
   (`trstctl --full-backup-dir=<incident-backup-dir>`) before making changes. The
   event log inside it is the immutable source of truth and forensic record;
   the PostgreSQL-state stream keeps auth, CA, approval, secret, policy, and outbox
   state recoverable too.
3. **Verify the audit chain.** trstctl's audit trail is a hash-linked, signed chain
   (R2.1). Verify it (`audit.VerifyChain`) to confirm the record has not been
   tampered with and to establish a trustworthy timeline of who did what
   (`Actor` is recorded on every event).
4. **Scope the blast radius.** Identify the affected credentials and everything that
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
   issuing CA key in the signer's key store; do not reuse the compromised one. The
   signer **persists and seals its CA key and preserves it across restarts** (R3.2),
   so rotation is a **deliberate re-key**, not an automatic restart side-effect:
   per the key ceremony, replace the signer's sealed key store with the new CA key,
   then restart the signer so it adopts it, and re-issue under the new CA.
4. **Revoke** suspect leaves through the served lifecycle path; OCSP answers change
   immediately and trusted revocation paths publish a fresh tenant CRL. If the CA
   itself is compromised, distribute a replacement CA bundle and re-issue under the
   new CA; CA-level revocation and cross-sign choreography remains an operator/key
   ceremony procedure.
5. **Re-issue** active credentials under the new CA and **redeploy** them to their
   targets.
6. **Recover** any lost state from backup ([DR runbook](../disaster-recovery.md)).

## Scenario: unexpected certificate (mis-issuance)

1. trstctl's **Certificate Transparency monitoring** watches your domains and raises
   an alert on issuance it does not recognize (library-level today; when served it
   notifies on unexpected issuance).
2. Confirm whether the certificate is yours (check inventory) or truly unexpected.
3. If unexpected and for your domain, treat it as a CA-trust incident: revoke,
   rotate if your CA issued it in error, and notify per policy.

## Scenario: leaked leaf credential or key

1. **Revoke** the affected certificate and **rotate** the credential (issue a
   replacement, deploy it, retire the old one on the lifecycle state machine).
2. **Audit** for misuse during the exposure window using the audit chain.
3. **Rotate any shared secrets** the credential could reach (use blast-radius scope).

## Communications & closeout

- Notify affected owners and relying parties per your disclosure policy
  ([SECURITY.md](https://github.com/imfeelingtheagi/trstctl/blob/main/SECURITY.md)).
- Capture a timeline from the audit chain; write a post-incident review with
  concrete follow-ups (shorter validity, tighter custody, added monitoring).
- Confirm `/readyz` is green and the inventory is consistent before closing.

## Quick reference

| Lever | Where | Served today? |
| --- | --- | --- |
| Stop new issuance | stop the signer (fails closed) | yes |
| Verify audit timeline | `audit.VerifyChain` (R2.1) | yes |
| Backup / restore | `trstctl --full-backup-dir` / `--full-restore-dir` | yes |
| Rotate the CA | m-of-n [key ceremony](key-ceremony.md) | library (Go API) |
| Revoke leaves (CRL/OCSP) | served revocation surface (`/ocsp/{tenant}`, `/crl/{tenant}`) | yes |
| Unexpected-issuance alert | CT monitoring | library |
