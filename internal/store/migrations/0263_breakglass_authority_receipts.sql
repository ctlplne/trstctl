-- Public CA material from immutable emergency rotation and cross-sign events.
-- Exact results survive a lost response without request-path event replay.
CREATE TABLE breakglass_authority_receipts (
    tenant_id UUID NOT NULL,
    ceremony_id UUID NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('rotation', 'cross_sign')),
    subject TEXT NOT NULL CHECK (subject <> ''),
    request_digest TEXT NOT NULL CHECK (request_digest <> ''),
    result JSONB NOT NULL CHECK (jsonb_typeof(result) = 'object'),
    event_sequence BIGINT NOT NULL CHECK (event_sequence > 0),
    completed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, ceremony_id)
);
CREATE UNIQUE INDEX breakglass_authority_receipts_source_idx
    ON breakglass_authority_receipts (tenant_id, event_sequence);
CREATE INDEX breakglass_authority_receipts_recent_idx
    ON breakglass_authority_receipts (tenant_id, event_sequence DESC);

ALTER TABLE breakglass_authority_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE breakglass_authority_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY breakglass_authority_receipts_isolation ON breakglass_authority_receipts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON breakglass_authority_receipts TO trstctl_app;

-- Warm upgrades replay only these two indexed event subjects through a finite
-- history cut. NULL means not yet examined, including N-1 deployments.
ALTER TABLE projection_checkpoint ADD COLUMN breakglass_authority_checked_through BIGINT
    CHECK (breakglass_authority_checked_through >= 0);
