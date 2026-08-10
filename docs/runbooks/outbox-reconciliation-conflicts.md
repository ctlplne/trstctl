# Runbook: quarantined outbox reconciliation conflicts

Use this runbook when the Incidents console shows **Quarantined receiver
commands**, or when
`GET /api/v1/incidents/outbox-reconciliation-conflicts` returns an item.

This is not a delivery retry or a dead letter. It means startup replay found an
immutable event asking a receiver to execute idempotency key `K`, while durable
outbox history already binds `K` to a different exact command. The receiver-key
guard refused the candidate. ELI5: the old numbered coat-check ticket already
belongs to one coat, so the control plane will not silently hand the same ticket
to a different coat.

## What the control plane guarantees

- The historical outbox row remains byte-for-byte authoritative. Reconciliation
  neither updates it nor executes the candidate payload.
- One deterministic `outbox.reconciliation_conflict.recorded` event and one
  tenant-scoped FORCE-RLS projection row record the refusal. They expose the
  source event, old outbox row, effect lanes, agent requirements, and SHA-256
  identities of both commands. They never expose a second executable payload.
- The source event is quarantined as one atomic unit. If it described several
  receiver commands, the transaction rolls all of them back; none are partly
  published.
- The reconciliation checkpoint advances past that quarantined source event.
  Other tenants and later unrelated work continue starting and reconciling.
- Repeated startup/reconciliation creates neither a second receiver command nor
  a second incident. Unexpected errors that are not this typed collision remain
  fatal, so the availability path does not turn corruption into success.

## Triage

1. Open **Incidents → Overview → Quarantined receiver commands**, or call the
   authenticated endpoint with an `incidents:read` token. The authenticated
   token's tenant is authoritative; `X-Tenant-ID` cannot select another tenant.
2. Record `source_event_id`, `source_event_sequence`, `source_event_type`,
   `idempotency_key`, and `existing_outbox_id` in the incident ticket.
3. Compare `existing_effect_lane` with `candidate_effect_lane`, both required
   agent role/ID fields, and the two payload SHA-256 values. Unequal hashes prove
   the envelopes differ; they are evidence identities, not values to execute.
4. Inspect the producer configuration that generated the source event. Common
   causes are a stable seed/request name reused after a resource received a new
   random ID, or a deployment job that derives one semantic idempotency key for
   two different targets. Fix that source before retrying.
5. Confirm unrelated health through `/readyz` and check the normal outbox/dead
   letter views. A healthy service plus this incident means the scoped command
   was refused as designed; it does not mean the intended external change ran.

## Safe remediation

Issue the intended operation again through its normal authenticated API or
console workflow with a **new unique `Idempotency-Key`** after correcting the
source identity/target binding. Confirm the new event names the intended
identity, effect lane, destination, and agent demand; then verify its ordinary
outbox receipt and endpoint readback.

Do not update or delete the old outbox row. Do not move the checkpoint manually.
Do not rewrite the immutable source event, copy the candidate payload into the
old row, or force-deliver it under the colliding key. Those actions destroy the
exactly-once meaning of the receiver key and can execute the wrong command while
leaving audit evidence that claims the opposite.

The quarantine row remains as immutable recovery evidence after the corrected
operation succeeds. Use the new operation's receipt plus the quarantine event as
the closure evidence in the incident record.
