# Respond to a key or certificate compromise

## Goal

When you finish this journey you will have **contained a compromised credential**:
the leaked certificate revoked and visible as `revoked` on the served surface, a
replacement issued and deployed, and the whole response captured as a sealed,
tamper-evident evidence pack. It is for the on-call operator who has just learned a
private key leaked, a certificate was mis-issued, or a CA may be compromised, and
needs to act safely under pressure. In plain terms: you preserve evidence, find
everything the bad credential can reach, replace-then-revoke in the right order so
you do not cause an outage, and — when a second person must sign off — gate the
action behind an approval.

> **In the console:** the `/incidents` screen runs this whole response — a served
> blast-radius preview for the compromised identity, replacement-before-revoke
> execution with the resulting evidence, and a break-glass reconciliation panel. See
> [The web console](../web-console.md).

## Before you start

- A running control plane and an API token, set up in
  [Getting started](../getting-started.md). Containment is a privileged action, so
  your principal needs issuance authority (the bootstrap token deliberately
  withholds it).
- Know which credential is affected. The blast-radius and revocation surfaces are
  described in [Incident response & just-in-time access](../features/incident-and-jit.md)
  and [Issuance & certificate authorities](../features/issuance-and-cas.md).
- Have the [incident-response runbook](../runbooks/incident-response.md) open — this
  journey is the happy-path version of it.

## Steps

1. **Declare the incident and preserve evidence first.** Before changing anything,
   take a full backup — the event log inside it is the immutable forensic record:

   ```sh
   trstctl --full-backup-dir=/backups/incident-$(date +%F)
   ```

   You should see a confirmation that the full backup was written. Keep it; you can
   restore from it later (see the [disaster-recovery runbook](../disaster-recovery.md)).

2. **Scope the blast radius.** Find the affected credential and everything that
   depends on it — read-only, so it changes nothing:

   ```sh
   trstctl-cli graph blast-radius cert:payments-tls
   ```

   You should see the affected resources grouped by kind. This is the same
   [credential graph](../features/incident-and-jit.md) the served incident workflow
   reads before it acts.

3. **Run the served containment workflow.** For a single leaked identity, the served
   workflow replaces-then-revokes idempotently — it issues and deploys a replacement
   first, then revokes the compromised credential, so nothing goes dark mid-incident.
   Put the details in a JSON file:

   ```json
   {
     "identity_id": "11111111-1111-1111-1111-111111111111",
     "reason": "private key export detected",
     "replacement_name": "payments-api-incident-replacement",
     "connector": "nginx",
     "target": "edge/prod/payments",
     "delivery_rollback_ref": "restore previous fullchain"
   }
   ```

   ```sh
   trstctl incidents executions execute -f incident.json
   ```

   You should get back an execution with a replacement id, a revocation-queue status,
   a connector delivery receipt, and a sealed audit bundle. The order is deliberate —
   do not shortcut it.

4. **Confirm the revocation is live.** Transitioning to revoked marks the certificate
   `revoked` in inventory and updates the published revocation status. Read it back:

   ```sh
   trstctl-cli certificates get 11111111-1111-1111-1111-111111111111
   ```

   You should see `status` read `"revoked"` with a `revoked_at` timestamp. Relying
   parties checking the served OCSP responder at `/ocsp/{tenant}` now get `revoked`,
   and the serial appears on the tenant CRL at `/crl/{tenant}` within the freshness
   window. The full revocation surface is in
   [Issuance & certificate authorities](../features/issuance-and-cas.md).

5. **Retrieve the sealed evidence pack.** Pull the recorded execution for your
   post-incident review:

   ```sh
   trstctl incidents executions get 22222222-2222-2222-2222-222222222222
   ```

   You should see the immutable evidence pack — replacement id, revocation status,
   delivery receipt, failed-target list, rollback references, and the sealed audit
   bundle.

6. **If the action needs a second pair of eyes (break-glass / JIT).** When dual
   control is enabled, a privileged issue or revoke is denied until a **distinct**
   approver signs off — a self-approval is rejected. The requester opens the request;
   a second operator approves it:

   ```sh
   curl -fksS -X POST \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{}' \
     https://localhost:8443/api/v1/identities/11111111-1111-1111-1111-111111111111/approvals
   ```

   You should see the approval recorded; the action proceeds only once a distinct
   approver has signed off. The four-eyes and just-in-time model is described in
   [Incident response & just-in-time access](../features/incident-and-jit.md).

7. **Use brokered access instead of standing credentials.** If the responder needs to
   inspect a database or host, open a short-lived privileged-access session instead of
   sharing a long-lived password or SSH key:

   ```sh
   curl -fksS -X POST \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: incident-2026-06-25-db-readonly" \
     -H "Content-Type: application/json" \
     -d '{"target_type":"postgres","target_id":"pg-main","role":"readonly","reason":"production incident 42","method":"k8s_sat","payload_base64":"...","ttl_seconds":900}' \
     https://localhost:8443/api/v1/access/sessions
   ```

   You should receive a session id, an expiry, and a one-time credential. Audit readers
   can later filter `pam.session.started` and `pam.session.expired`; after expiry the
   database role is revoked or the SSH certificate is past its validity window.

## Where next

- [Run trstctl in production](run-in-production.md)
- [Issue your first certificate](first-certificate.md)

**Journey:** J9
**Steps through:** F31, F32, F33, F34, F47, F18, F19
