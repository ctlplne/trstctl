-- migrate: no-transaction
-- 0036_certificate_issuance_idempotency.sql - durable issuance retry correlation.
--
-- CORRECT-001: if a process dies after a signer-backed certificate is recorded
-- but before the idempotency result row is completed, a retry must find the
-- already-recorded certificate before it can re-enter the signer. This column is
-- projected from certificate.recorded events, so the correlation survives rebuild.

ALTER TABLE certificates
    ADD COLUMN IF NOT EXISTS issuance_idempotency_key text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS certificate_der bytea NOT NULL DEFAULT '\x';

CREATE INDEX CONCURRENTLY IF NOT EXISTS certificates_issuance_idempotency_idx
    ON certificates (tenant_id, issuance_idempotency_key, created_at)
    WHERE issuance_idempotency_key <> '';
