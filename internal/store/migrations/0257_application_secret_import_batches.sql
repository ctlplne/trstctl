-- One durable command and one event for the complete import. Name reservations
-- serialize with single-secret command fences before the broker append; the
-- projector commits every sealed row and the independent receipt in one tenant
-- transaction, then releases all reservations.
CREATE TABLE application_secret_import_batches (
    tenant_id UUID NOT NULL,
    event_id UUID NOT NULL,
    tenant_epoch UUID NOT NULL,
    request_binding CHAR(64) NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    command_payload BYTEA NOT NULL,
    actor JSONB NOT NULL,
    actor_subject_ref TEXT NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, event_id),
    CHECK (request_binding ~ '^[0-9a-f]{64}$'),
    CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (octet_length(command_payload) > 0),
    CHECK (length(actor_subject_ref) > 0)
);

CREATE TABLE application_secret_import_name_fences (
    tenant_id UUID NOT NULL,
    secret_name TEXT NOT NULL,
    event_id UUID NOT NULL,
    PRIMARY KEY (tenant_id, secret_name),
    FOREIGN KEY (tenant_id, event_id)
        REFERENCES application_secret_import_batches (tenant_id, event_id)
        ON DELETE CASCADE,
    CHECK (length(btrim(secret_name)) > 0)
);
CREATE INDEX application_secret_import_name_fences_event_idx
    ON application_secret_import_name_fences (tenant_id, event_id);

CREATE TABLE application_secret_import_receipts (
    tenant_id UUID NOT NULL,
    event_id UUID NOT NULL,
    semantic_sha256 CHAR(64) NOT NULL,
    request_binding CHAR(64) NOT NULL,
    items JSONB NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, event_id),
    CHECK (semantic_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (request_binding ~ '^[0-9a-f]{64}$'),
    CHECK (jsonb_typeof(items) = 'array')
);

ALTER TABLE application_secret_import_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE application_secret_import_batches FORCE ROW LEVEL SECURITY;
CREATE POLICY application_secret_import_batches_isolation ON application_secret_import_batches
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

ALTER TABLE application_secret_import_name_fences ENABLE ROW LEVEL SECURITY;
ALTER TABLE application_secret_import_name_fences FORCE ROW LEVEL SECURITY;
CREATE POLICY application_secret_import_name_fences_isolation ON application_secret_import_name_fences
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

ALTER TABLE application_secret_import_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE application_secret_import_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY application_secret_import_receipts_isolation ON application_secret_import_receipts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON application_secret_import_batches TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON application_secret_import_name_fences TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON application_secret_import_receipts TO trstctl_app;
