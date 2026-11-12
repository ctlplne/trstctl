-- OD-8 (A205-L1): a standing approval lets one SPIRE server's upstream
-- authority plugin have its CA CSRs signed by one trstctl CA authority without
-- a key ceremony per CSR. A ceremony grants it once (opt-in, quorum approved);
-- it binds the authority, the caller's principal (the plugin's token
-- subject), the SPIRE trust domain every signed CA must name, and the CA spec
-- with its maximum lifetime, and it expires. Every signing under it is in the
-- event log and counted here; an issuers:write administrator can revoke it at
-- once. The table is the projection of ca.upstream_standing_approval.granted,
-- .revoked and .signed, and rebuilds from the event log.
CREATE TABLE IF NOT EXISTS ca_upstream_standing_approvals (
    tenant_id       uuid        NOT NULL,
    id              uuid        NOT NULL,
    ca_id           uuid        NOT NULL,
    principal       text        NOT NULL CHECK (principal <> '' AND length(principal) <= 512),
    trust_domain    text        NOT NULL CHECK (trust_domain <> '' AND length(trust_domain) <= 255),
    spec            jsonb       NOT NULL,
    max_ttl_seconds bigint      NOT NULL CHECK (max_ttl_seconds > 0),
    ceremony_id     text        NOT NULL CHECK (ceremony_id <> ''),
    granted_by      text        NOT NULL DEFAULT '',
    granted_at      timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    revoked_by      text        NOT NULL DEFAULT '',
    revoke_reason   text        NOT NULL DEFAULT '',
    signings        bigint      NOT NULL DEFAULT 0 CHECK (signings >= 0),
    last_signed_at  timestamptz,
    event_sequence  bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id),
    CHECK (expires_at > granted_at)
);
CREATE INDEX IF NOT EXISTS ca_upstream_standing_approvals_by_principal
    ON ca_upstream_standing_approvals (tenant_id, ca_id, principal);
ALTER TABLE ca_upstream_standing_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE ca_upstream_standing_approvals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ca_upstream_standing_approvals_isolation ON ca_upstream_standing_approvals;
CREATE POLICY ca_upstream_standing_approvals_isolation ON ca_upstream_standing_approvals
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON ca_upstream_standing_approvals TO trstctl_app;
