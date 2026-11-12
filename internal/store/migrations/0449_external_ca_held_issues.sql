-- N1-L1: issuances an external CA holds for a manager's approval (AD CS's
-- "taken under submission"), by the CA's own request id, so an issuance can
-- be resumed once the request is approved. Projections of
-- certificate.external_issue_held and certificate.external_issue_resumed.
-- issue_key, request_binding and key_origin are the held issuance's own, so a
-- resumed certificate is recorded under the issuance the caller is waiting on.
CREATE TABLE IF NOT EXISTS external_ca_held_issues (
    tenant_id        uuid        NOT NULL,
    authority_id     text        NOT NULL,
    ca_request_id    integer     NOT NULL CHECK (ca_request_id > 0),
    issue_key        text        NOT NULL,
    request_binding  text        NOT NULL,
    key_origin       text        NOT NULL DEFAULT '',
    dns_names        text[]      NOT NULL DEFAULT '{}',
    status           text        NOT NULL DEFAULT 'held' CHECK (status IN ('held', 'issued', 'denied')),
    serial           text        NOT NULL DEFAULT '',
    held_at          timestamptz NOT NULL,
    resolved_at      timestamptz,
    event_sequence   bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, authority_id, ca_request_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS external_ca_held_issues_key_idx ON external_ca_held_issues (tenant_id, authority_id, issue_key);
CREATE INDEX IF NOT EXISTS external_ca_held_issues_held_idx ON external_ca_held_issues (tenant_id, authority_id, held_at DESC);
ALTER TABLE external_ca_held_issues ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_ca_held_issues FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS external_ca_held_issues_isolation ON external_ca_held_issues;
CREATE POLICY external_ca_held_issues_isolation ON external_ca_held_issues
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON external_ca_held_issues TO trstctl_app;
