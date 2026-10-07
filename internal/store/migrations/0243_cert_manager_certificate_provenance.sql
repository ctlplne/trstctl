-- Authenticated cert-manager CertificateRequest observations are event
-- projections. Retain exact request/Certificate UIDs and the issued leaf digest
-- after cert-manager garbage-collects its CertificateRequest.
ALTER TABLE kubernetes_controller_posture DROP CONSTRAINT kubernetes_controller_posture_capability_check;
ALTER TABLE kubernetes_controller_posture ADD CONSTRAINT kubernetes_controller_posture_capability_check
    CHECK (capability IN ('certificate-signing-requests', 'trust-bundles', 'cert-manager-certificate-requests'));

CREATE TABLE kubernetes_certificate_provenance (
    tenant_id          uuid NOT NULL,
    cluster_id         text NOT NULL CHECK (cluster_id ~ '^sha256:[0-9a-f]{64}$'),
    namespace          text NOT NULL,
    request_name       text NOT NULL,
    request_uid        text NOT NULL,
    certificate_name   text NOT NULL,
    certificate_uid    text NOT NULL,
    fingerprint        text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    controller_id      uuid NOT NULL,
    report_id          uuid NOT NULL,
    observed_at        timestamptz NOT NULL,
    event_sequence     bigint NOT NULL CHECK (event_sequence >= 0),
    PRIMARY KEY (tenant_id, cluster_id, request_uid, fingerprint)
);

CREATE INDEX kubernetes_certificate_provenance_fingerprint_idx
    ON kubernetes_certificate_provenance (tenant_id, fingerprint, observed_at DESC);

ALTER TABLE kubernetes_certificate_provenance ENABLE ROW LEVEL SECURITY;
ALTER TABLE kubernetes_certificate_provenance FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_certificate_provenance_isolation ON kubernetes_certificate_provenance
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON kubernetes_certificate_provenance TO trstctl_app;
