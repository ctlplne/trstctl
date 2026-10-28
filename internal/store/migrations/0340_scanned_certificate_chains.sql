-- A211: the issuer certificates a network scan saw served with a leaf, kept when
-- agent_channel.probe_scanned_certificates is on so the leaf's CRL and OCSP
-- answers can be verified against its own issuer. Public certificates only, each
-- checked against the hash the relay reported. A projection of
-- discovery.certificate_chain.observed; the latest observation per leaf.
CREATE TABLE IF NOT EXISTS scanned_certificate_chains (
    tenant_id        uuid        NOT NULL,
    leaf_fingerprint text        NOT NULL CHECK (leaf_fingerprint ~ '^[0-9a-f]{64}$'),
    position         integer     NOT NULL CHECK (position BETWEEN 1 AND 4),
    certificate_der  bytea       NOT NULL CHECK (octet_length(certificate_der) BETWEEN 1 AND 16384),
    certificate_sha256 text      NOT NULL CHECK (certificate_sha256 ~ '^[0-9a-f]{64}$'),
    observed_at      timestamptz NOT NULL,
    event_sequence   bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, leaf_fingerprint, position)
);
ALTER TABLE scanned_certificate_chains ENABLE ROW LEVEL SECURITY;
ALTER TABLE scanned_certificate_chains FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scanned_certificate_chains_isolation ON scanned_certificate_chains;
CREATE POLICY scanned_certificate_chains_isolation ON scanned_certificate_chains
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON scanned_certificate_chains TO trstctl_app;

-- A211: a revocation probe answer is either an endpoint's health, checked
-- through a representative certificate, or one scanned certificate checked for
-- its own serial; a CRL answer says whether it lists that serial.
ALTER TABLE revocation_endpoint_health ADD COLUMN IF NOT EXISTS scope text NOT NULL DEFAULT 'endpoint';
ALTER TABLE revocation_endpoint_health ADD COLUMN IF NOT EXISTS certificate_listed boolean;
