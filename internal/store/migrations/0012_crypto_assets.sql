-- Cryptographic Bill of Materials (F52, S6.8): the catalog of cryptographic
-- *usage* discovered across the environment — TLS protocol versions, cipher
-- suites, certificate keys, and host crypto configuration — classified by
-- strength, post-quantum exposure, and policy compliance. This is posture
-- across assets trstctl does not necessarily issue, distinct from the cert/SSH
-- inventory. Per AN-1 each row carries tenant_id and is confined by row-level
-- security.
--
-- An asset is identified within a tenant by its signature (kind + location +
-- the specific algorithm/protocol/cipher), so re-scanning refreshes the row.
-- quantum_vulnerable and out_of_policy are first-class columns: they are the
-- signals the PQC migration (F57) and risk scoring (F19) consume.
CREATE TABLE crypto_assets (
    id                 uuid PRIMARY KEY,
    tenant_id          uuid NOT NULL,
    signature          text NOT NULL,
    kind               text NOT NULL DEFAULT '',
    location           text NOT NULL DEFAULT '',
    algorithm          text NOT NULL DEFAULT '',
    key_bits           integer NOT NULL DEFAULT 0,
    protocol           text NOT NULL DEFAULT '',
    cipher             text NOT NULL DEFAULT '',
    library            text NOT NULL DEFAULT '',
    strength           text NOT NULL DEFAULT '',
    quantum_vulnerable boolean NOT NULL DEFAULT false,
    out_of_policy      boolean NOT NULL DEFAULT false,
    reasons            text[] NOT NULL DEFAULT '{}',
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, signature)
);

ALTER TABLE crypto_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE crypto_assets FORCE ROW LEVEL SECURITY;

CREATE POLICY crypto_assets_isolation ON crypto_assets
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- "Which crypto is weak or quantum-vulnerable" is the primary posture query.
CREATE INDEX crypto_assets_posture_idx ON crypto_assets (tenant_id, quantum_vulnerable, out_of_policy);

GRANT SELECT, INSERT, UPDATE, DELETE ON crypto_assets TO trstctl_app;
