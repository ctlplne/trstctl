-- M4 prerequisite: a durable single-use record for JWT-style machine credentials.
-- An oidc or jwt machine login (and the token exchange) records each accepted
-- token here until it expires; presenting it again is refused across processes
-- and restarts. The key is a digest (issuer + jti, else the whole token); no
-- token bytes are stored.
CREATE TABLE IF NOT EXISTS machine_credential_replays (
    tenant_id  uuid        NOT NULL,
    method     text        NOT NULL CHECK (method <> ''),
    key_digest text        NOT NULL CHECK (key_digest <> ''),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, method, key_digest)
);
CREATE INDEX IF NOT EXISTS machine_credential_replays_expiry ON machine_credential_replays (tenant_id, expires_at);
ALTER TABLE machine_credential_replays ENABLE ROW LEVEL SECURITY;
ALTER TABLE machine_credential_replays FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS machine_credential_replays_isolation ON machine_credential_replays;
CREATE POLICY machine_credential_replays_isolation ON machine_credential_replays
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON machine_credential_replays TO trstctl_app;
