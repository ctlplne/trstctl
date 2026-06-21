-- migrate: no-transaction
-- Active API-token lookup for member offboarding and token inventory.
--
-- online-safe: CONCURRENTLY avoids blocking writes on the live api_tokens table;
-- this no-transaction migration is idempotent and safe to retry before the
-- schema_migrations ledger row.

CREATE INDEX CONCURRENTLY IF NOT EXISTS api_tokens_subject_active_idx
    ON api_tokens (tenant_id, subject, id)
    WHERE revoked_at IS NULL;
