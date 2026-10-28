-- A205: JWT signing keys that SPIRE servers publish through the trstctl
-- upstream authority plugin. Each server publishes its own key and receives
-- every key the tenant's servers have published, so servers that share a trust
-- domain through trstctl verify each other's JWT-SVIDs. The table is the
-- projection of spiffe.upstream_jwt_key.published and rebuilds from the event
-- log. Public keys only.
CREATE TABLE IF NOT EXISTS spiffe_upstream_jwt_keys (
    tenant_id      uuid        NOT NULL,
    key_id         text        NOT NULL CHECK (key_id <> '' AND length(key_id) <= 256),
    public_key_der bytea       NOT NULL CHECK (length(public_key_der) > 0),
    -- expires_at is NULL for a key SPIRE published without an expiry.
    expires_at     timestamptz,
    tainted        boolean     NOT NULL DEFAULT false,
    published_by   text        NOT NULL DEFAULT '',
    published_at   timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, key_id)
);
CREATE INDEX IF NOT EXISTS spiffe_upstream_jwt_keys_by_expiry
    ON spiffe_upstream_jwt_keys (tenant_id, expires_at);
ALTER TABLE spiffe_upstream_jwt_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE spiffe_upstream_jwt_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS spiffe_upstream_jwt_keys_isolation ON spiffe_upstream_jwt_keys;
CREATE POLICY spiffe_upstream_jwt_keys_isolation ON spiffe_upstream_jwt_keys
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON spiffe_upstream_jwt_keys TO trstctl_app;
