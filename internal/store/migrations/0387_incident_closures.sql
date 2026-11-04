-- P13: incidents closed in trstctl. Projection of incident.execution.closed.
-- Closing an incident may also resolve the ServiceNow incident its response
-- dispatch opened; that is an outbox effect whose state reads from the outbox
-- row.
CREATE TABLE IF NOT EXISTS incident_closures (
    tenant_id       uuid        NOT NULL,
    incident_id     text        NOT NULL,
    resolution      text        NOT NULL,
    closed_by       text        NOT NULL,
    servicenow      boolean     NOT NULL DEFAULT false,
    closed_at       timestamptz NOT NULL,
    event_sequence  bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, incident_id)
);
ALTER TABLE incident_closures ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_closures FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS incident_closures_isolation ON incident_closures;
CREATE POLICY incident_closures_isolation ON incident_closures
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON incident_closures TO trstctl_app;
