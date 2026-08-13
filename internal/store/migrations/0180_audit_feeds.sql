-- 0180_audit_feeds.sql -- AUD-52 durable native Splunk HEC/Sentinel delivery.
--
-- Destinations are event-sourced tenant read models. Authentication stays an
-- opaque credential reference. Exact delivery batches get their own projected
-- receipt row and one same-transaction outbox command performs the network call.

CREATE TABLE IF NOT EXISTS audit_feed_destinations (
    id                       uuid        NOT NULL,
    tenant_id                uuid        NOT NULL,
    name                     text        NOT NULL,
    provider                 text        NOT NULL,
    endpoint_url             text        NOT NULL,
    token_ref                text        NOT NULL,
    interval_seconds         integer     NOT NULL,
    batch_size               integer     NOT NULL,
    enabled                  boolean     NOT NULL DEFAULT true,
    allow_private_endpoint   boolean     NOT NULL DEFAULT false,
    private_egress_cidrs     jsonb       NOT NULL DEFAULT '[]'::jsonb,
    config_event_sequence    bigint      NOT NULL,
    next_run_at              timestamptz NOT NULL,
    last_queued_sequence     bigint      NOT NULL DEFAULT 0,
    last_delivered_sequence  bigint      NOT NULL DEFAULT 0,
    lag_records              integer     NOT NULL DEFAULT 0,
    last_batch_id            uuid,
    last_outbox_key          text        NOT NULL DEFAULT '',
    last_status              text        NOT NULL DEFAULT 'not_started',
    last_attempt_at          timestamptz,
    last_delivered_at        timestamptz,
    last_error_code          text        NOT NULL DEFAULT '',
    created_at               timestamptz NOT NULL,
    updated_at               timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT audit_feed_destination_required_chk
        CHECK (name <> '' AND endpoint_url <> '' AND token_ref <> ''),
    CONSTRAINT audit_feed_destination_provider_chk
        CHECK (provider IN ('splunk-hec', 'sentinel')),
    CONSTRAINT audit_feed_destination_interval_chk
        CHECK (interval_seconds >= 60),
    CONSTRAINT audit_feed_destination_batch_chk
        CHECK (batch_size BETWEEN 1 AND 500),
    CONSTRAINT audit_feed_destination_status_chk
        CHECK (last_status IN ('not_started', 'queued', 'delivered', 'failed')),
    CONSTRAINT audit_feed_destination_cursor_chk
        CHECK (last_queued_sequence >= 0 AND last_delivered_sequence >= 0
               AND last_delivered_sequence <= last_queued_sequence AND lag_records >= 0)
);

CREATE TABLE IF NOT EXISTS audit_feed_deliveries (
    batch_id                 uuid        NOT NULL,
    tenant_id                uuid        NOT NULL,
    destination_id          uuid        NOT NULL,
    provider                text        NOT NULL,
    start_sequence          bigint      NOT NULL,
    end_sequence            bigint      NOT NULL,
    record_count            integer     NOT NULL,
    chain_head              text        NOT NULL,
    outbox_idempotency_key  text        NOT NULL,
    status                   text        NOT NULL,
    queued_at                timestamptz NOT NULL,
    accepted_at              timestamptz,
    collector_request_id     text        NOT NULL DEFAULT '',
    error_code               text        NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, batch_id),
    CONSTRAINT audit_feed_delivery_provider_chk
        CHECK (provider IN ('splunk-hec', 'sentinel')),
    CONSTRAINT audit_feed_delivery_range_chk
        CHECK (start_sequence > 0 AND end_sequence >= start_sequence AND record_count > 0),
    CONSTRAINT audit_feed_delivery_status_chk
        CHECK (status IN ('queued', 'delivered', 'failed')),
    CONSTRAINT audit_feed_delivery_destination_fk
        FOREIGN KEY (tenant_id, destination_id)
        REFERENCES audit_feed_destinations (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE audit_feed_destinations ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_feed_destinations FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_feed_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_feed_deliveries FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_feed_destinations_isolation ON audit_feed_destinations
    USING (tenant_id::text = current_setting('trstctl.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('trstctl.tenant_id', true));
CREATE POLICY audit_feed_deliveries_isolation ON audit_feed_deliveries
    USING (tenant_id::text = current_setting('trstctl.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('trstctl.tenant_id', true));

CREATE INDEX audit_feed_destinations_due_idx
    ON audit_feed_destinations (tenant_id, next_run_at, id)
    WHERE enabled AND last_status NOT IN ('queued', 'failed');
CREATE UNIQUE INDEX audit_feed_destinations_tenant_name_idx
    ON audit_feed_destinations (tenant_id, name);
CREATE UNIQUE INDEX audit_feed_deliveries_outbox_key_idx
    ON audit_feed_deliveries (tenant_id, outbox_idempotency_key);
CREATE INDEX audit_feed_deliveries_destination_time_idx
    ON audit_feed_deliveries (tenant_id, destination_id, queued_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON audit_feed_destinations TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_feed_deliveries TO trstctl_app;
