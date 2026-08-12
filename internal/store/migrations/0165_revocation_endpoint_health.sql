-- AUD-38 / epic R1: replayable health for the CRL and OCSP endpoints that
-- inventoried certificates tell relying parties to use. This is a projection:
-- the immutable revocation.health.observed event is the authority.
CREATE TABLE revocation_endpoint_health (
    tenant_id              uuid        NOT NULL,
    target_key             text        NOT NULL,
    protocol               text        NOT NULL,
    endpoint               text        NOT NULL,
    issuer_subject         text        NOT NULL,
    issuer_fingerprint     text        NOT NULL DEFAULT '',
    certificate_id         uuid        NOT NULL,
    certificate_subject    text        NOT NULL,
    certificate_fingerprint text       NOT NULL,
    certificate_serial     text        NOT NULL,
    status                 text        NOT NULL,
    detail_code            text        NOT NULL,
    latency_ms             bigint      NOT NULL DEFAULT 0,
    this_update            timestamptz,
    next_update            timestamptz,
    signature_verified     boolean     NOT NULL DEFAULT false,
    revoked_count          integer     NOT NULL DEFAULT 0,
    response_status        text        NOT NULL DEFAULT '',
    responder_subject      text        NOT NULL DEFAULT '',
    probe_id               uuid        NOT NULL,
    bucket                 text        NOT NULL,
    batch_index            integer     NOT NULL,
    batch_count            integer     NOT NULL,
    observed_by_agent_id   uuid        NOT NULL,
    observed_by_agent_name text        NOT NULL,
    evidence_digest        text        NOT NULL,
    observed_at            timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, target_key),
    CONSTRAINT revocation_endpoint_health_target_key_chk
        CHECK (target_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT revocation_endpoint_health_protocol_chk
        CHECK (protocol IN ('crl', 'ocsp')),
    CONSTRAINT revocation_endpoint_health_status_chk
        CHECK (status IN ('fresh', 'expiring', 'stale', 'unreachable', 'unparseable')),
    CONSTRAINT revocation_endpoint_health_response_status_chk
        CHECK (response_status IN ('', 'good', 'revoked', 'unknown')),
    CONSTRAINT revocation_endpoint_health_counts_chk
        CHECK (latency_ms >= 0 AND revoked_count >= 0 AND batch_index >= 1 AND batch_count >= batch_index),
    CONSTRAINT revocation_endpoint_health_evidence_chk
        CHECK (evidence_digest ~ '^[0-9a-f]{64}$')
);

ALTER TABLE revocation_endpoint_health ENABLE ROW LEVEL SECURITY;
ALTER TABLE revocation_endpoint_health FORCE ROW LEVEL SECURITY;

CREATE POLICY revocation_endpoint_health_isolation ON revocation_endpoint_health
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX revocation_endpoint_health_status_idx
    ON revocation_endpoint_health (tenant_id, status, observed_at DESC, target_key);

GRANT SELECT, INSERT, UPDATE, DELETE ON revocation_endpoint_health TO trstctl_app;

COMMENT ON TABLE revocation_endpoint_health IS
    'Tenant-isolated projection of relay-verified CRL and OCSP reachability, signature, status, and freshness evidence (epic R1).';
