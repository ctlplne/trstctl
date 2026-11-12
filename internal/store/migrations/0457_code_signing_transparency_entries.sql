-- P9-L2: the transparency-log entry each signature landed in. The Rekor
-- handler verifies the log's receipt (the entry UUID binds the logged body,
-- the log ID the configured log key, the signed entry timestamp the entry)
-- before codesign.transparency_recorded is appended; this table is its
-- projection, one entry per signing operation, served as the bundle stock
-- cosign checks offline instead of skipping the transparency log.
CREATE TABLE IF NOT EXISTS code_signing_transparency_entries (
    tenant_id              uuid        NOT NULL,
    operation_id           text        NOT NULL CHECK (length(btrim(operation_id)) BETWEEN 1 AND 200),
    entry_uuid             text        NOT NULL CHECK (entry_uuid ~ '^[0-9a-f]{64}([0-9a-f]{16})?$'),
    log_index              bigint      NOT NULL CHECK (log_index >= 0),
    log_id                 text        NOT NULL CHECK (log_id ~ '^[0-9a-f]{64}$'),
    integrated_time        bigint      NOT NULL CHECK (integrated_time > 0),
    body                   text        NOT NULL CHECK (length(body) BETWEEN 1 AND 1048576),
    signed_entry_timestamp bytea       NOT NULL CHECK (length(signed_entry_timestamp) BETWEEN 1 AND 1024),
    recorded_at            timestamptz NOT NULL,
    event_sequence         bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, operation_id)
);

ALTER TABLE code_signing_transparency_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE code_signing_transparency_entries FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS code_signing_transparency_entries_isolation ON code_signing_transparency_entries;
CREATE POLICY code_signing_transparency_entries_isolation ON code_signing_transparency_entries
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON code_signing_transparency_entries TO trstctl_app;
