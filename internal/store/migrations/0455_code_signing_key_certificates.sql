-- P9-L1: a code-signing key's certificate chain attached through the API.
-- The chain (leaf first) is checked against the key's public key and the
-- codeSigning usage before codesign.certificate_attached is appended; this
-- table is its projection, newest attachment per key, and is read before the
-- chain configured beside the key, so a chain is attached or rotated without
-- changing configuration or restarting.
CREATE TABLE IF NOT EXISTS code_signing_key_certificates (
    tenant_id        uuid        NOT NULL,
    key_id           text        NOT NULL CHECK (length(btrim(key_id)) BETWEEN 1 AND 200),
    chain_der        bytea[]     NOT NULL CHECK (cardinality(chain_der) BETWEEN 1 AND 10),
    leaf_fingerprint text        NOT NULL CHECK (leaf_fingerprint ~ '^[0-9a-f]{64}$'),
    not_after        timestamptz NOT NULL,
    attached_by      text        NOT NULL DEFAULT '',
    attached_at      timestamptz NOT NULL,
    event_sequence   bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, key_id)
);

ALTER TABLE code_signing_key_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE code_signing_key_certificates FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS code_signing_key_certificates_isolation ON code_signing_key_certificates;
CREATE POLICY code_signing_key_certificates_isolation ON code_signing_key_certificates
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON code_signing_key_certificates TO trstctl_app;
