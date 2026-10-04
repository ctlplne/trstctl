-- The current delegation tuple is the authorization projection. Keep each
-- grant episode separately so a later grant cannot erase earlier revocation
-- evidence. Startup replays retained authority events into this derived table
-- before the Provider plane serves requests.
CREATE TABLE provider_operator_grant_episodes (
    tenant_id uuid NOT NULL,
    grant_event_id text NOT NULL CHECK (grant_event_id <> ''),
    operator_id text NOT NULL,
    customer_tenant_id text NOT NULL,
    operation text NOT NULL,
    source text NOT NULL,
    granted_by text NOT NULL,
    granted_at timestamptz NOT NULL,
    expires_at timestamptz,
    last_used_at timestamptz,
    revoked_at timestamptz,
    revoked_by text NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, grant_event_id, operator_id, customer_tenant_id, operation)
);
CREATE INDEX provider_operator_grant_episodes_by_operator
    ON provider_operator_grant_episodes (tenant_id, operator_id, customer_tenant_id, operation, granted_at);
CREATE INDEX provider_operator_grant_episodes_active
    ON provider_operator_grant_episodes (tenant_id, operator_id, customer_tenant_id, operation)
    WHERE revoked_at IS NULL;
ALTER TABLE provider_operator_grant_episodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_operator_grant_episodes FORCE ROW LEVEL SECURITY;
CREATE POLICY provider_operator_grant_episodes_isolation ON provider_operator_grant_episodes
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON provider_operator_grant_episodes TO trstctl_app;
COMMENT ON TABLE provider_operator_grant_episodes IS
    'Event-projected Provider grant episodes in the fixed authority partition. Authorization reads provider_operator_delegations, never this history table.';
