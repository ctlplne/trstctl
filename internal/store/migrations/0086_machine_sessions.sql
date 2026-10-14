-- 0086_machine_sessions.sql -- event-sourced machine-login session read model
-- plus the per-tenant auth-method disable overlay (C-S3, DA-02).
--
-- machine_sessions is the projection of secrets.session.started/.revoked. It
-- stores session metadata only: the login exchange's returned session is a
-- scope receipt, not a bearer credential, and no credential material is ever
-- projected. Revocation is advisory ledger state (the session is not consumed
-- by later API calls); enforcement lives in the auth-method overlay below and
-- in API-token revocation.
--
-- machine_auth_method_overrides is the projection of
-- secrets.auth_method.disabled/.enabled: a tenant-level overlay on the
-- config-declared method set that the login path consults before accepting a
-- credential. Methods themselves stay declared in server config (AN-9-adjacent
-- honesty: the console projects and overlays, it does not edit config).

CREATE TABLE IF NOT EXISTS machine_sessions (
    tenant_id   uuid NOT NULL,
    id          text NOT NULL,
    principal   text NOT NULL,
    method      text NOT NULL,
    scopes      text[] NOT NULL DEFAULT '{}',
    status      text NOT NULL,
    issued_at   timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    revoked_by  text NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id)
);

ALTER TABLE machine_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE machine_sessions FORCE ROW LEVEL SECURITY;

CREATE POLICY machine_sessions_isolation ON machine_sessions
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX IF NOT EXISTS machine_sessions_issued_idx
    ON machine_sessions (tenant_id, issued_at DESC, id);

CREATE INDEX IF NOT EXISTS machine_sessions_status_idx
    ON machine_sessions (tenant_id, status, expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON machine_sessions TO trstctl_app;

CREATE TABLE IF NOT EXISTS machine_auth_method_overrides (
    tenant_id   uuid NOT NULL,
    method_name text NOT NULL,
    disabled    boolean NOT NULL DEFAULT false,
    updated_at  timestamptz NOT NULL,
    updated_by  text NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, method_name)
);

ALTER TABLE machine_auth_method_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE machine_auth_method_overrides FORCE ROW LEVEL SECURITY;

CREATE POLICY machine_auth_method_overrides_isolation ON machine_auth_method_overrides
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON machine_auth_method_overrides TO trstctl_app;
