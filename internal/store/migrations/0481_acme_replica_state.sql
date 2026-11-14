-- P15-L7: the ACME state replicas must agree on at the moment they act.
-- acme_nonces holds each nonce a replica minted (by its SHA-256 digest, never
-- the nonce) until it expires or a replica redeems it, so any replica takes a
-- nonce once. acme_finalize_claims holds the one live finalize of an order,
-- leased to the process that claimed it, so two replicas never issue twice
-- for one order; a claim whose holder stopped expires.
CREATE TABLE IF NOT EXISTS acme_nonces (
    tenant_id    uuid        NOT NULL,
    nonce_digest text        NOT NULL CHECK (nonce_digest <> ''),
    expires_at   timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, nonce_digest)
);
CREATE INDEX IF NOT EXISTS acme_nonces_expiry ON acme_nonces (tenant_id, expires_at);
ALTER TABLE acme_nonces ENABLE ROW LEVEL SECURITY;
ALTER TABLE acme_nonces FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS acme_nonces_isolation ON acme_nonces;
CREATE POLICY acme_nonces_isolation ON acme_nonces
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON acme_nonces TO trstctl_app;

CREATE TABLE IF NOT EXISTS acme_finalize_claims (
    tenant_id     uuid        NOT NULL,
    order_id      text        NOT NULL CHECK (order_id <> ''),
    holder        text        NOT NULL CHECK (holder <> ''),
    claimed_until timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, order_id)
);
CREATE INDEX IF NOT EXISTS acme_finalize_claims_expiry ON acme_finalize_claims (tenant_id, claimed_until);
ALTER TABLE acme_finalize_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE acme_finalize_claims FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS acme_finalize_claims_isolation ON acme_finalize_claims;
CREATE POLICY acme_finalize_claims_isolation ON acme_finalize_claims
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON acme_finalize_claims TO trstctl_app;
