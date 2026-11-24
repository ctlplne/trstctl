-- SPDX-License-Identifier: BUSL-1.1

-- A pre-upgrade event can contain text PostgreSQL cannot project. Keep the
-- immutable event in JetStream and record which tenant's read model is unsafe.
-- The projection cursor may then continue for other tenants, while tenant
-- service admission refuses the affected tenant until a verified recovery.
CREATE TABLE projection_tenant_quarantines (
    tenant_id UUID PRIMARY KEY,
    first_failed_seq BIGINT NOT NULL CHECK (first_failed_seq > 0),
    reason_code TEXT NOT NULL CHECK (reason_code IN ('nul_text', 'invalid_utf8')),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE projection_tenant_quarantines ENABLE ROW LEVEL SECURITY;
ALTER TABLE projection_tenant_quarantines FORCE ROW LEVEL SECURITY;
CREATE POLICY projection_tenant_quarantines_isolation ON projection_tenant_quarantines
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT ON projection_tenant_quarantines TO trstctl_app;
