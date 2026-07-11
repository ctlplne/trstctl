-- 0084_notification_delivery_state.sql -- durable notification command and
-- per-channel delivery authority (AN-1/AN-2/AN-5/AN-6).
--
-- notification_test_operations preserves the authenticated command identity and
-- original queued response metadata after the bounded API-idempotency and outbox
-- rows are collected. notification_delivery_receipts records one successful
-- receiver effect per channel, so retrying a partially successful fan-out skips
-- channels that already acknowledged the alert.

CREATE TABLE notification_test_operations (
    tenant_id             uuid NOT NULL,
    id                    text NOT NULL,
    request_binding       text NOT NULL,
    channel_id            text NOT NULL,
    destination           text NOT NULL,
    outbox_id             bigint NOT NULL,
    credential_configured boolean NOT NULL DEFAULT false,
    queued_at             timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX notification_test_operations_queued_idx
    ON notification_test_operations (tenant_id, queued_at DESC, id);

ALTER TABLE notification_test_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_test_operations FORCE ROW LEVEL SECURITY;

CREATE POLICY notification_test_operations_isolation ON notification_test_operations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON notification_test_operations TO trstctl_app;

CREATE TABLE notification_delivery_receipts (
    tenant_id                    uuid NOT NULL,
    id                           text NOT NULL,
    destination                  text NOT NULL,
    notification_key_digest      text NOT NULL,
    payload_digest               text NOT NULL,
    channel                      text NOT NULL,
    outbox_id                    bigint,
    attempts                     integer NOT NULL DEFAULT 0,
    delivered_at                 timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX notification_delivery_receipts_channel_idx
    ON notification_delivery_receipts (tenant_id, channel, delivered_at DESC, id);

ALTER TABLE notification_delivery_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_delivery_receipts FORCE ROW LEVEL SECURITY;

CREATE POLICY notification_delivery_receipts_isolation ON notification_delivery_receipts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON notification_delivery_receipts TO trstctl_app;
