# Runbook: outbox dead letters (OPS-DLQ-001)

**Alert:** `TrstctlOutboxDeadLetterDepth` — `trstctl_outbox_deadletter_depth > 0 for 15m`,
labeled by `tenant_id` and `destination`.

An outbox row is dead-lettered when it exhausts its delivery attempts: its
`status` becomes `failed`, it is never dispatched again, and — per AN-6 — it is
never silently deleted. The gauge counts those rows per tenant/destination; the
retention sweeper (`internal/outboxgc`) reclaims only eligible `delivered` rows,
so a dead letter stays visible until an operator acts. A delivered event-derived
secret-sync outbox row may also age out: its immutable queued/terminal events and
terminal projected job retain the outcome/order. Migration-derived negative-order
rows remain as FIFO evidence until tenant offboarding, and failed secret-sync
evidence remains visible.

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
     duplicate to one effect). Non-secret-sync destinations replay by resetting
     the row:
     `UPDATE outbox SET status = 'pending', attempts = 0, next_attempt_at = now()
      WHERE id = $1 AND status = 'failed';` — safe for exactly the same reason.
   - **`secret.sync.*` → inspect receiver authority, then usually submit a fresh
     sync.** Never reset or delete the failed outbox row or its
     `secret_sync_jobs` row. Migration 0153 makes terminal state irreversible
     because that row is also the tenant+target FIFO record. For a current
     event-derived failure with `secret_sync_receiver_effect_state =
     'failure_authorized'`, fix the target, read the current source version, then
     use the supported sync API with a new `Idempotency-Key`. This creates a new
     event-ordered command instead of reviving retained ciphertext. A negative
     migration-derived row with `effect_possible` is different: the old release
     left no proof that receiver I/O was absent or finished, so a fresh command is
     deliberately retained behind that barrier. Keep the target blocked and
     escalate for provider-specific authenticated readback/reconciliation;
     generic trstctl code cannot manufacture the missing proof, and offboarding
     also refuses while a receiver generation may still complete. Never
     manufacture `failure_authorized` with SQL. After a fresh command actually
     succeeds, attach its job/event ids to the incident and acknowledge or
     narrowly silence the old dead-letter alert series; do not make the gauge
     disappear by editing history.
   - **Effect no longer wanted (target decommissioned, tenant offboarded) →
     sweep.** Record the decision in the incident/audit trail, then delete the
     exact rows by id. Never bulk-delete by status alone; the row ids in the
     audit trail are the evidence the effect was consciously dropped. This manual
     sweep does not apply to `secret.sync.*`; keep that immutable order evidence
     until the supported tenant-offboarding workflow removes the tenant.
4. The gauge re-samples on the next health probe; a drained ordinary bucket
   returns to zero and the alert clears. A remediated secret-sync bucket keeps its
   historical failed count, so close the incident through the alerting system's
   exact-series acknowledgment/silence recorded in step 3.

## Why there is no automatic sweep

Dead letters are the at-least-once ledger's memory of side effects the
platform PROMISED but could not perform. Automatically deleting them would
convert "temporarily broken" into "silently never happened". The sweep is
therefore an explicit operator decision, and the replay path is idempotent so
choosing replay is always safe to try first.
