-- 0041_incident_executions.sql -- served incident remediation evidence.
--
-- incident_executions is a read model projected from incident.execution.recorded
-- events. It stores operational evidence only: identity ids, graph impact JSON,
-- delivery receipt ids, rollback references, failed target labels, and the sealed
-- audit evidence bundle. It must never carry certificate/key/secret bytes.

CREATE TABLE IF NOT EXISTS incident_executions (
    id                       uuid PRIMARY KEY,
    tenant_id                uuid NOT NULL,
    compromised_identity_id  uuid NOT NULL,
    replacement_identity_id  uuid,
    connector_delivery_id    uuid,
    status                   text NOT NULL,
    phase                    text NOT NULL,
    reason                   text NOT NULL DEFAULT '',
    blast_radius             jsonb NOT NULL DEFAULT '{}'::jsonb,
    revocation_status        text NOT NULL DEFAULT '',
    evidence_bundle_format   text NOT NULL DEFAULT '',
    evidence_bundle          text NOT NULL DEFAULT '',
    failed_targets           text[] NOT NULL DEFAULT '{}',
    rollback_refs            text[] NOT NULL DEFAULT '{}',
    idempotency_key          text NOT NULL DEFAULT '',
    created_by               text NOT NULL DEFAULT '',
    created_at               timestamptz NOT NULL,
    updated_at               timestamptz NOT NULL
);

ALTER TABLE incident_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_executions FORCE ROW LEVEL SECURITY;

CREATE POLICY incident_executions_isolation ON incident_executions
    USING (tenant_id::text = current_setting('trstctl.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('trstctl.tenant_id', true));

CREATE INDEX IF NOT EXISTS incident_executions_tenant_updated_idx
    ON incident_executions (tenant_id, updated_at DESC, id);

CREATE INDEX IF NOT EXISTS incident_executions_compromised_identity_idx
    ON incident_executions (tenant_id, compromised_identity_id, updated_at DESC, id);

GRANT SELECT, INSERT, UPDATE, DELETE ON incident_executions TO trstctl_app;
