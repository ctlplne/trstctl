-- A95: tenant-scoped break-glass with dual consent.
--
-- A Provider's emergency access to a customer is approved by two Provider
-- custodians. A customer may require its OWN consent as well: a standing
-- policy row, the Provider requests it sees (projected from the Provider's
-- authority event under this tenant), and its people's decisions per grant.
-- All three are projected from the customer's event lane and confined by RLS.
CREATE TABLE IF NOT EXISTS provider_access_policy (
    tenant_id              uuid        PRIMARY KEY,
    require_tenant_consent boolean     NOT NULL DEFAULT false,
    approvals              integer     NOT NULL DEFAULT 2 CHECK (approvals >= 1),
    set_by                 text        NOT NULL DEFAULT '',
    set_at                 timestamptz NOT NULL
);
ALTER TABLE provider_access_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_access_policy FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_access_policy_isolation ON provider_access_policy;
CREATE POLICY provider_access_policy_isolation ON provider_access_policy
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON provider_access_policy TO trstctl_app;

CREATE TABLE IF NOT EXISTS provider_access_requests (
    tenant_id      uuid        NOT NULL,
    grant_id       text        NOT NULL,
    operator_email text        NOT NULL DEFAULT '',
    reason         text        NOT NULL DEFAULT '',
    requested_at   timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, grant_id)
);
ALTER TABLE provider_access_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_access_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_access_requests_isolation ON provider_access_requests;
CREATE POLICY provider_access_requests_isolation ON provider_access_requests
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON provider_access_requests TO trstctl_app;

CREATE TABLE IF NOT EXISTS provider_access_consents (
    tenant_id  uuid        NOT NULL,
    grant_id   text        NOT NULL,
    subject    text        NOT NULL,
    approve    boolean     NOT NULL,
    reason     text        NOT NULL DEFAULT '',
    decided_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, grant_id, subject)
);
ALTER TABLE provider_access_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_access_consents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_access_consents_isolation ON provider_access_consents;
CREATE POLICY provider_access_consents_isolation ON provider_access_consents
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON provider_access_consents TO trstctl_app;
