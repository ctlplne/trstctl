-- MSP-2 part 2: every usage push the Provider's billing sync makes, one row per
-- customer, target and closed period. A signable period is queued once (its
-- outbox entry is keyed by target and period, so a second sweep cannot queue it
-- again) and then delivered or failed; an unsignable period is held with its
-- reason and never sent. The row names the company the period was queued for,
-- so delivery can refuse a period whose customer has since been remapped. The
-- table is the projection of provider.billing_sync.queued / .held /
-- .delivered / .failed and rebuilds from the event log.
CREATE TABLE IF NOT EXISTS provider_billing_sync_pushes (
    tenant_id           uuid        NOT NULL,
    target_id           text        NOT NULL CHECK (target_id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    period_start        timestamptz NOT NULL,
    period_end          timestamptz NOT NULL,
    status              text        NOT NULL CHECK (status IN ('queued', 'held', 'delivered', 'failed')),
    external_company_id text        NOT NULL DEFAULT '' CHECK (length(external_company_id) <= 128),
    evidence_digest     text        NOT NULL DEFAULT '' CHECK (length(evidence_digest) <= 128),
    reason              text        NOT NULL DEFAULT '' CHECK (length(reason) <= 2000),
    response_status     integer     NOT NULL DEFAULT 0,
    first_event_id      text        NOT NULL DEFAULT '',
    event_sequence      bigint      NOT NULL CHECK (event_sequence > 0),
    updated_at          timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, target_id, period_start),
    CHECK (period_end > period_start)
);
CREATE INDEX IF NOT EXISTS provider_billing_sync_pushes_recent_idx
    ON provider_billing_sync_pushes (tenant_id, updated_at DESC);

ALTER TABLE provider_billing_sync_pushes ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_billing_sync_pushes FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS provider_billing_sync_pushes_tenant_isolation ON provider_billing_sync_pushes;
CREATE POLICY provider_billing_sync_pushes_tenant_isolation ON provider_billing_sync_pushes
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON provider_billing_sync_pushes TO trstctl_app;

COMMENT ON TABLE provider_billing_sync_pushes IS
    'MSP-2: each customer usage period the Provider billing sync queued, held, delivered or failed per target.';
