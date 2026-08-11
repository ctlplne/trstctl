-- Approval-request notifications were added to the boot outbox reconciler after
-- older binaries had already advanced this deployment-wide cursor past those
-- events. Rewind exactly once on upgrade so immutable approval.requested history
-- can backfill any notification intent lost between Append and its PostgreSQL
-- projection transaction. Every reconciled receiver key is strict and
-- idempotent; already-persisted lifecycle and notification commands remain
-- untouched, while a conflicting old binding is quarantined by the reconciler.

UPDATE outbox_reconciliation_checkpoint
   SET reconciled_seq = 0,
       updated_at = now()
 WHERE id = 1
   AND reconciled_seq <> 0;
