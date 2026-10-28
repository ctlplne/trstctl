-- A215: how an inventory row that held no certificate bytes got them — from
-- the tenant's own CA mint that retained them, or from the endpoint serving the
-- certificate — only ever bytes that hash to the row's fingerprint. A projection
-- of certificate.der.recovered; one row per certificate.
CREATE TABLE IF NOT EXISTS certificate_der_recoveries (
    tenant_id      uuid        NOT NULL,
    fingerprint    text        NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    method         text        NOT NULL CHECK (method IN ('ca_ledger', 'endpoint')),
    evidence       text        NOT NULL CHECK (evidence <> ''),
    recovered_at   timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, fingerprint)
);
ALTER TABLE certificate_der_recoveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificate_der_recoveries FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certificate_der_recoveries_isolation ON certificate_der_recoveries;
CREATE POLICY certificate_der_recoveries_isolation ON certificate_der_recoveries
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON certificate_der_recoveries TO trstctl_app;
