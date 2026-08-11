-- 0146_operation_approval_principal_decision.sql -- one immutable decision per principal.
--
-- A principal cannot both approve and deny the same exact request.  The event
-- projection treats a retry of the same decision as idempotent and rejects any
-- different decision, event, reason, or timestamp as an idempotency conflict.
--
-- online-safe: operation_approval_decisions is introduced by immediately preceding
-- migration 0145. Older binaries cannot write it, the migration advisory lock
-- serializes upgraded nodes, and the process does not serve requests until the
-- entire migration set finishes, so this table is empty here. Keeping the index
-- and ledger write in one transaction also makes a failed first boot retry-safe.

CREATE UNIQUE INDEX IF NOT EXISTS operation_approval_decisions_principal_once_idx
    ON operation_approval_decisions (tenant_id, request_id, approver);
