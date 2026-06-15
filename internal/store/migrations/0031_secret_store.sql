-- 0031_secret_store.sql — the served application-secret store (GAP-006 / EXC-WIRE
-- secrets): the relational, RLS-isolated backing for the served secrets API
-- (/api/v1/secrets/store/...) that the secretsdk/secrets engine mounts on the
-- running binary. Until now the secrets/identity frameworks were library-only with
-- zero importers on the served path (GAP-006); this is the table the served secret
-- store reads and writes through.
--
-- Like 0014_credentials (the system upstream-CA/connector secret store) the value
-- is held ONLY as envelope-encrypted ciphertext (internal/crypto/seal): the
-- plaintext never touches this table; `sealed` is wrapped by the deployment KEK and
-- bound to (tenant_id, name, version) as AAD, so a blob cannot be lifted to another
-- row/tenant and still open (AN-8). A rotation bumps `version` and replaces the
-- sealed bytes in place; `version` is the monotonic rotation counter surfaced to the
-- caller (the plaintext of prior versions is overwritten — this is a current-value
-- store, not a history of plaintexts).
--
-- Per AN-1 every row carries tenant_id and isolation is enforced by row-level
-- security that is ENABLED and FORCE-d (the owner cannot bypass it), with a
-- WITH CHECK matching the USING clause so writes are confined too (TENANT-008). With
-- the tenant GUC unset the predicate is NULL and no rows match — fail closed.

CREATE TABLE IF NOT EXISTS secret_store (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL,
    name       text NOT NULL,                 -- the secret's logical path/name within the tenant
    sealed     bytea NOT NULL,                -- envelope-encrypted ciphertext; never plaintext
    version    integer NOT NULL DEFAULT 1,    -- monotonic rotation counter (bumped on each rotate)
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

ALTER TABLE secret_store ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_store FORCE  ROW LEVEL SECURITY;

-- Fail closed: with the tenant GUC unset the predicate is NULL and no rows match.
CREATE POLICY secret_store_isolation ON secret_store
    USING (tenant_id = current_setting('trustctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trustctl.tenant_id', true)::uuid);

CREATE INDEX IF NOT EXISTS secret_store_tenant_name_idx
    ON secret_store (tenant_id, name);

GRANT SELECT, INSERT, UPDATE, DELETE ON secret_store TO trustctl_app;
