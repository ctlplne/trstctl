-- Tenant access administration (JOURNEY-003): governed RA setup needs a served
-- member/role/API-token surface. Members are a tenant read model projected from
-- tenant.member.* events. API tokens already existed; this migration adds
-- revocation evidence so offboarding can retire bearer access without deleting
-- the audit-relevant token row.

CREATE TABLE tenant_members (
    tenant_id      uuid NOT NULL,
    subject        text NOT NULL,
    display_name   text NOT NULL DEFAULT '',
    email          text NOT NULL DEFAULT '',
    roles          text[] NOT NULL DEFAULT '{}',
    source         text NOT NULL DEFAULT 'manual',
    status         text NOT NULL DEFAULT 'active',
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    offboarded_at  timestamptz,
    offboarded_by  text NOT NULL DEFAULT '',
    offboard_reason text NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, subject)
);

ALTER TABLE tenant_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_members FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_members_isolation ON tenant_members
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX tenant_members_status_idx ON tenant_members (tenant_id, status, subject);

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_members TO trstctl_app;

ALTER TABLE api_tokens
    ADD COLUMN IF NOT EXISTS revoked_at timestamptz,
    ADD COLUMN IF NOT EXISTS revoked_by text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS revocation_reason text NOT NULL DEFAULT '';
