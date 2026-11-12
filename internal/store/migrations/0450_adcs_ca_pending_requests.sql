-- N1-L2: the requests an AD CS CA holds for a manager's approval, from the
-- latest relay read of its database that listed them: one row per CA, the list
-- newest first (at most 500, each with its request id, template, requested
-- name and requester), whether the read cut it short, and when it was read.
-- Projection of adcs.ca_database.ingested; the event sequence keeps it
-- monotone.
CREATE TABLE IF NOT EXISTS adcs_ca_pending_requests (
    tenant_id      uuid        NOT NULL,
    ca_config      text        NOT NULL,
    requests       jsonb       NOT NULL DEFAULT '[]'::jsonb,
    truncated      boolean     NOT NULL DEFAULT false,
    observed_at    timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, ca_config)
);
ALTER TABLE adcs_ca_pending_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE adcs_ca_pending_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS adcs_ca_pending_requests_isolation ON adcs_ca_pending_requests;
CREATE POLICY adcs_ca_pending_requests_isolation ON adcs_ca_pending_requests
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON adcs_ca_pending_requests TO trstctl_app;
