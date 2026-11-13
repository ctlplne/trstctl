-- MSP-14: each customer's documentation record in each documentation target
-- (IT Glue, Hudu): the organization it was written under, the record's ID
-- there, the digest of what was last written (an unchanged inventory writes
-- nothing), the certificate count and next expiry it showed, and whether the
-- last sync succeeded. One row per customer and target. The table is the
-- projection of provider.doc_record.recorded and rebuilds from the event log.
CREATE TABLE IF NOT EXISTS provider_doc_records (
    tenant_id      uuid        NOT NULL,
    target_id      text        NOT NULL CHECK (target_id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    org_id         text        NOT NULL DEFAULT '' CHECK (length(org_id) <= 128),
    record_id      text        NOT NULL DEFAULT '' CHECK (length(record_id) <= 128),
    digest         text        NOT NULL DEFAULT '' CHECK (digest = '' OR digest ~ '^[0-9a-f]{64}$'),
    certificates   integer     NOT NULL DEFAULT 0 CHECK (certificates >= 0),
    next_expiry    timestamptz,
    status         text        NOT NULL CHECK (status IN ('synced', 'failed')),
    reason         text        NOT NULL DEFAULT '' CHECK (length(reason) <= 2000),
    synced_at      timestamptz,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    updated_at     timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, target_id)
);

ALTER TABLE provider_doc_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_doc_records FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS provider_doc_records_tenant_isolation ON provider_doc_records;
CREATE POLICY provider_doc_records_tenant_isolation ON provider_doc_records
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON provider_doc_records TO trstctl_app;

COMMENT ON TABLE provider_doc_records IS
    'MSP-14: each customer''s certificate-inventory record in each documentation target and the state of its last sync.';
