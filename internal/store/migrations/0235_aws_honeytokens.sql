-- AWS decoys reuse the inert honeytoken inventory while their IAM authority and
-- CloudTrail coverage remain separately identifiable. The access key secret is
-- never stored in this table or in the event stream.
ALTER TABLE honey_tokens
    ADD COLUMN kind text NOT NULL DEFAULT 'native' CHECK (kind IN ('native', 'aws')),
    ADD COLUMN aws_account_config_id text,
    ADD COLUMN aws_account_id text,
    ADD COLUMN aws_access_key_id text,
    ADD COLUMN aws_lease_id text,
    ADD COLUMN aws_regions text[],
    ADD COLUMN aws_poll_interval_seconds integer,
    ADD COLUMN alarm_generation integer NOT NULL DEFAULT 0;

ALTER TABLE honey_tokens ADD CONSTRAINT honey_tokens_aws_complete CHECK (
    (kind = 'native' AND aws_account_config_id IS NULL AND aws_account_id IS NULL
     AND aws_access_key_id IS NULL AND aws_lease_id IS NULL AND aws_regions IS NULL
     AND aws_poll_interval_seconds IS NULL)
    OR
    (kind = 'aws' AND aws_account_config_id IS NOT NULL AND aws_account_id ~ '^[0-9]{12}$'
     AND aws_access_key_id IS NOT NULL AND aws_lease_id IS NOT NULL
     AND cardinality(aws_regions) BETWEEN 1 AND 32
     AND aws_poll_interval_seconds BETWEEN 60 AND 3600)
);
-- One immutable scan command yields one page event. Each projection advances
-- this cursor and queues the next page or timed polling cycle in one transaction.
CREATE TABLE aws_honey_scans (
    tenant_id uuid NOT NULL,
    honey_id uuid NOT NULL REFERENCES honey_tokens(id) ON DELETE CASCADE,
    region text NOT NULL,
    cycle bigint NOT NULL DEFAULT 0,
    page integer NOT NULL DEFAULT 0,
    next_token text NOT NULL DEFAULT '',
    window_start timestamptz,
    window_end timestamptz,
    watermark timestamptz NOT NULL,
    last_success_at timestamptz,
    gap_since timestamptz,
    PRIMARY KEY (tenant_id, honey_id, region)
);
ALTER TABLE aws_honey_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE aws_honey_scans FORCE ROW LEVEL SECURITY;
CREATE POLICY aws_honey_scans_isolation ON aws_honey_scans
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON aws_honey_scans TO trstctl_app;

CREATE TABLE aws_honey_uses (
    tenant_id uuid NOT NULL,
    honey_id uuid NOT NULL REFERENCES honey_tokens(id) ON DELETE CASCADE,
    event_id text NOT NULL,
    region text NOT NULL,
    event_source text NOT NULL,
    event_name text NOT NULL,
    source_ip_address text NOT NULL,
    user_agent text NOT NULL,
    error_code text NOT NULL,
    event_time timestamptz NOT NULL,
    detected_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, event_id)
);
CREATE INDEX aws_honey_uses_by_decoy ON aws_honey_uses (tenant_id, honey_id, event_time DESC);
ALTER TABLE aws_honey_uses ENABLE ROW LEVEL SECURITY;
ALTER TABLE aws_honey_uses FORCE ROW LEVEL SECURITY;
CREATE POLICY aws_honey_uses_isolation ON aws_honey_uses
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON aws_honey_uses TO trstctl_app;

-- Operational distributed quota coordination; this table grants no product
-- authority and is deliberately outside the event-sourced read model.
CREATE TABLE aws_honey_cloudtrail_slots (
    tenant_id uuid NOT NULL,
    account_id text NOT NULL,
    region text NOT NULL,
    next_allowed_at timestamptz NOT NULL DEFAULT (now() - interval '1 second'),
    PRIMARY KEY (tenant_id, account_id, region)
);
ALTER TABLE aws_honey_cloudtrail_slots ENABLE ROW LEVEL SECURITY;
ALTER TABLE aws_honey_cloudtrail_slots FORCE ROW LEVEL SECURITY;
CREATE POLICY aws_honey_cloudtrail_slots_isolation ON aws_honey_cloudtrail_slots
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON aws_honey_cloudtrail_slots TO trstctl_app;
