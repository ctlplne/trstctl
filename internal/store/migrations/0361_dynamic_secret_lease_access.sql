-- G2: what each active dynamic-secret lease reaches, read from its target by the
-- leader's access worker: the target (a PostgreSQL database or an AWS IAM role),
-- the login the lease holds there, and the grants or policies the target reports
-- for it. A projection of dynsecret.lease.access_observed; one row per lease, the
-- latest observation. A target that could not be read is 'unknown' with a
-- closed-set reason, never an empty grant list.
CREATE TABLE IF NOT EXISTS dynamic_secret_lease_access (
    tenant_id      uuid        NOT NULL,
    lease_id       text        NOT NULL CHECK (lease_id <> ''),
    provider       text        NOT NULL CHECK (provider <> ''),
    status         text        NOT NULL CHECK (status IN ('resolved', 'unknown', 'unsupported')),
    target_kind    text        NOT NULL DEFAULT '',
    target_ref     text        NOT NULL DEFAULT '',
    login          text        NOT NULL DEFAULT '',
    grants         text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(grants) <= 200),
    truncated      integer     NOT NULL DEFAULT 0 CHECK (truncated >= 0),
    reason         text        NOT NULL DEFAULT '',
    checked_at     timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, lease_id),
    CONSTRAINT dynamic_secret_lease_access_unknown_has_reason CHECK (status <> 'unknown' OR reason <> '')
);
ALTER TABLE dynamic_secret_lease_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE dynamic_secret_lease_access FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS dynamic_secret_lease_access_isolation ON dynamic_secret_lease_access;
CREATE POLICY dynamic_secret_lease_access_isolation ON dynamic_secret_lease_access
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON dynamic_secret_lease_access TO trstctl_app;
