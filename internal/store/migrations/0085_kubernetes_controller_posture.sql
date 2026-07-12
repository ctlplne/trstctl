-- 0085_kubernetes_controller_posture.sql -- latest metadata-only Kubernetes
-- controller observations, projected from kubernetes.controller.posture_reported.

CREATE TABLE kubernetes_controller_posture (
    tenant_id                    uuid NOT NULL,
    controller_id                uuid NOT NULL,
    cluster_id                   text NOT NULL CHECK (cluster_id ~ '^sha256:[0-9a-f]{64}$'),
    capability                   text NOT NULL CHECK (capability IN ('certificate-signing-requests', 'trust-bundles')),
    report_id                    uuid NOT NULL,
    reconcile_complete           boolean NOT NULL,
    failure_code                 text NOT NULL DEFAULT '',
    reconcile_interval_seconds   integer NOT NULL CHECK (reconcile_interval_seconds BETWEEN 1 AND 86400),
    resources                    jsonb NOT NULL DEFAULT '[]'::jsonb
                                 CHECK (jsonb_typeof(resources) = 'array' AND jsonb_array_length(resources) <= 2000),
    reported_at                  timestamptz NOT NULL,
    event_sequence               bigint NOT NULL DEFAULT 0 CHECK (event_sequence >= 0),
    CHECK ((reconcile_complete AND failure_code = '') OR
           (NOT reconcile_complete AND failure_code IN ('not_reconciled', 'reconcile_failed'))),
    PRIMARY KEY (tenant_id, cluster_id, capability)
);

CREATE INDEX kubernetes_controller_posture_capability_idx
    ON kubernetes_controller_posture (tenant_id, capability, reported_at DESC, controller_id, cluster_id);

ALTER TABLE kubernetes_controller_posture ENABLE ROW LEVEL SECURITY;
ALTER TABLE kubernetes_controller_posture FORCE ROW LEVEL SECURITY;

CREATE POLICY kubernetes_controller_posture_isolation ON kubernetes_controller_posture
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON kubernetes_controller_posture TO trstctl_app;
