-- Sealed credentials at rest (R3.1): upstream CA and connector secrets — API
-- keys, passwords, client secrets — are stored ONLY as envelope-encrypted blobs
-- (internal/crypto/seal). The plaintext never touches this table; `sealed` is
-- ciphertext wrapped by the deployment's KEK. Per AN-1 every row carries a
-- tenant_id and is confined by row-level security.
CREATE TABLE credentials (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    scope      text NOT NULL,             -- e.g. 'issuer' | 'connector'
    ref        text NOT NULL,             -- the owning issuer/target id
    name       text NOT NULL,             -- credential field, e.g. 'api_key' | 'password'
    sealed     bytea NOT NULL,            -- envelope-encrypted ciphertext; never plaintext
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, scope, ref, name)
);

ALTER TABLE credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE credentials FORCE ROW LEVEL SECURITY;

-- Fail closed: with the tenant GUC unset the predicate is NULL and no rows match.
CREATE POLICY credentials_isolation ON credentials
    USING (tenant_id = current_setting('certctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON credentials TO certctl_app;
