-- 0047_secret_shares.sql — durable one-time shares for the served secrets API.
--
-- A share token is a bearer secret returned only to the creator. The database stores
-- only SHA-256(token) plus the envelope-encrypted payload, so PostgreSQL can survive
-- an API restart without ever learning the token or plaintext (AN-8). Redemption is
-- a DELETE ... RETURNING under tenant RLS, which makes the share single-use even
-- when two workers race.

CREATE TABLE IF NOT EXISTS secret_shares (
    tenant_id    uuid NOT NULL,
    token_sha256 text NOT NULL,
    share_id     text NOT NULL,
    sealed       bytea NOT NULL,
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, token_sha256)
);

ALTER TABLE secret_shares ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_shares FORCE  ROW LEVEL SECURITY;

CREATE POLICY secret_shares_isolation ON secret_shares
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX IF NOT EXISTS secret_shares_expiry_idx
    ON secret_shares (tenant_id, expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON secret_shares TO trstctl_app;
