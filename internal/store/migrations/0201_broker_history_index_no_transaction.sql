-- migrate: no-transaction
-- Build the broker history lookup while ordinary inventory writes stay live.
-- Repeating this file before its ledger receipt is recorded is safe. The runner
-- verifies the concurrent index is ready/valid before accepting the migration.
CREATE INDEX CONCURRENTLY IF NOT EXISTS certificates_broker_history_idx
    ON certificates (tenant_id, created_at DESC, id DESC)
    WHERE issuance_idempotency_key LIKE 'broker-issue:%';
ALTER TABLE certificates VALIDATE CONSTRAINT certificates_broker_issuance_object;
