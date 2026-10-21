-- 0289_vault_cubbyhole.sql — the Vault/OpenBao shim's per-token cubbyhole.
--
-- A cubbyhole entry belongs to one API token: the row is keyed by the token's
-- SHA-256 and the entry path, the value is envelope-encrypted under the tenant
-- key domain (AN-8), and reads with any other token see nothing. expires_at
-- follows the token's own expiry when it has one; NULL means the entry lives
-- until deleted or until the token is revoked and its rows purged.

CREATE TABLE IF NOT EXISTS vault_cubbyhole (
    tenant_id    uuid NOT NULL,
    token_sha256 text NOT NULL,
    path         text NOT NULL,
    sealed       bytea NOT NULL,
    expires_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, token_sha256, path)
);

ALTER TABLE vault_cubbyhole ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_cubbyhole FORCE  ROW LEVEL SECURITY;

CREATE POLICY vault_cubbyhole_isolation ON vault_cubbyhole
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX IF NOT EXISTS vault_cubbyhole_expiry_idx
    ON vault_cubbyhole (tenant_id, expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON vault_cubbyhole TO trstctl_app;
