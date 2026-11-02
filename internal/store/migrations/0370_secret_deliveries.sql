-- A238: secret delivery reports. A consumer (an agent rendering files, a CSI
-- volume) reports, per secret, the version it wrote ("injected") and the version
-- its application proved it uses ("verified"); the two are kept apart so a
-- written file is never mistaken for a working application. Projection of
-- secret.delivery.reported.
CREATE TABLE IF NOT EXISTS secret_deliveries (
    tenant_id        uuid        NOT NULL,
    consumer         text        NOT NULL CHECK (consumer <> ''),
    name             text        NOT NULL CHECK (name <> ''),
    injected_version integer     NOT NULL DEFAULT 0 CHECK (injected_version >= 0),
    injected_at      timestamptz,
    verified_version integer     NOT NULL DEFAULT 0 CHECK (verified_version >= 0),
    verified_at      timestamptz,
    reported_by      text        NOT NULL DEFAULT '',
    event_sequence   bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, consumer, name)
);
ALTER TABLE secret_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_deliveries FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secret_deliveries_isolation ON secret_deliveries;
CREATE POLICY secret_deliveries_isolation ON secret_deliveries
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON secret_deliveries TO trstctl_app;
