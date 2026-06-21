-- migrate: no-transaction
-- Subject-erasure lookup indexes on live access tables.
--
-- online-safe: CONCURRENTLY avoids blocking writes on populated tenant_members
-- and api_tokens tables; IF NOT EXISTS makes this no-transaction migration
-- retry-safe before the schema_migrations ledger row is written.

CREATE INDEX CONCURRENTLY IF NOT EXISTS tenant_members_subject_ref_idx
    ON tenant_members (tenant_id, subject_ref)
    WHERE subject_ref <> '';

CREATE INDEX CONCURRENTLY IF NOT EXISTS api_tokens_subject_ref_idx
    ON api_tokens (tenant_id, subject_ref)
    WHERE subject_ref <> '';
