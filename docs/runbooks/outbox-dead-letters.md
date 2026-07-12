# Runbook: outbox dead letters (OPS-DLQ-001)

**Alert:** `TrstctlOutboxDeadLetterDepth` — `trstctl_outbox_deadletter_depth > 0 for 15m`,
labeled by `tenant_id` and `destination`.

An outbox row is dead-lettered when it exhausts its delivery attempts: its
`status` becomes `failed`, it is never dispatched again, and — per AN-6 — it is
never silently deleted. The gauge counts those rows per tenant/destination; the
retention sweeper (`internal/outboxgc`) reclaims only `delivered` rows, so a
dead letter stays visible until an operator acts.

## Triage

1. Identify the bucket from the alert labels (`tenant_id`, `destination`).
2. Inspect the rows' `last_error` (system operation, RLS-bypassing):
   `SELECT id, idempotency_key, attempts, last_error, created_at FROM outbox
    WHERE status = 'failed' AND tenant_id = $1 AND destination = $2
    ORDER BY created_at;`
3. Decide per bucket:
   - **Downstream outage now fixed → replay.** Notification dispatches replay
     through the served API: `POST /api/v1/notifications/{id}/requeue`
     (idempotent; the recorded `idempotency_key` lets the receiver collapse a
     duplicate to one effect). Other destinations replay by resetting the row:
     `UPDATE outbox SET status = 'pending', attempts = 0, next_attempt_at = now()
      WHERE id = $1 AND status = 'failed';` — safe for exactly the same reason.
   - **Effect no longer wanted (target decommissioned, tenant offboarded) →
     sweep.** Record the decision in the incident/audit trail, then delete the
     exact rows by id. Never bulk-delete by status alone; the row ids in the
     audit trail are the evidence the effect was consciously dropped.
4. The gauge re-samples on the next health probe; a drained bucket returns to
   zero and the alert clears.

## Why there is no automatic sweep

Dead letters are the at-least-once ledger's memory of side effects the
platform PROMISED but could not perform. Automatically deleting them would
convert "temporarily broken" into "silently never happened". The sweep is
therefore an explicit operator decision, and the replay path is idempotent so
choosing replay is always safe to try first.
