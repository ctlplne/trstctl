-- A145: the timestamping authority's certificates.
--
-- A projection of tsa.certificate.registered and tsa.certificate.revoked. Each
-- TSA certificate is also an entry of its issuing CA's ledger (ca_issued_certs),
-- so the CA's CRL and OCSP responder answer for it; this table adds what the TSA
-- needs to rotate: the signer handle holding each certificate's key. Rebuilds
-- from the event log.
CREATE TABLE IF NOT EXISTS tsa_certificates (
    tenant_id      uuid        NOT NULL,
    serial         text        NOT NULL CHECK (serial ~ '^[0-9a-f]{1,64}$'),
    ca_id          text        NOT NULL CHECK (ca_id <> ''),
    handle         text        NOT NULL CHECK (handle <> ''),
    cert_der       bytea       NOT NULL,
    cert_sha256    text        NOT NULL CHECK (cert_sha256 ~ '^[0-9a-f]{64}$'),
    not_before     timestamptz NOT NULL,
    not_after      timestamptz NOT NULL,
    registered_at  timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    revoked_at     timestamptz,
    reason_code    integer,
    PRIMARY KEY (tenant_id, serial),
    CHECK ((revoked_at IS NULL) = (reason_code IS NULL))
);
CREATE INDEX IF NOT EXISTS tsa_certificates_by_registration
    ON tsa_certificates (tenant_id, event_sequence DESC);
ALTER TABLE tsa_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE tsa_certificates FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tsa_certificates_isolation ON tsa_certificates;
CREATE POLICY tsa_certificates_isolation ON tsa_certificates
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON tsa_certificates TO trstctl_app;

-- The TSA certificate's CA ledger row is bound to its registration event, like
-- every other row a known writer mints.
ALTER TABLE ca_issued_certs DROP CONSTRAINT IF EXISTS ca_issued_event_provenance_shape;
ALTER TABLE ca_issued_certs ADD CONSTRAINT ca_issued_event_provenance_shape CHECK (
    (issuance_event_id IS NULL AND issuance_event_type IS NULL)
    OR (issuance_event_id IS NOT NULL AND issuance_event_id <> ''
        AND issuance_event_type IS NOT NULL AND issuance_event_type IN (
            'certificate.recorded', 'ca.certificate.issued',
            'ca.endentity.issued', 'edge.delegation.issued', 'tsa.certificate.registered'))
);
