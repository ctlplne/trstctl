-- Tenant-authored notification channel lifecycle (TRACE-007/F29).
-- The table stores delivery metadata and credential references only. Secret
-- values remain in the secret store or an operator-approved secret backend.

CREATE TABLE notification_channels (
    tenant_id      uuid NOT NULL,
    id             text NOT NULL,
    channel_type   text NOT NULL,
    label          text NOT NULL,
    endpoint_url   text NOT NULL DEFAULT '',
    credential_ref text NOT NULL DEFAULT '',
    enabled        boolean NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX notification_channels_tenant_type_idx
    ON notification_channels (tenant_id, channel_type, enabled);

ALTER TABLE notification_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_channels FORCE ROW LEVEL SECURITY;

CREATE POLICY notification_channels_isolation ON notification_channels
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON notification_channels TO trstctl_app;
