-- N1: decisions on requests an AD CS template holds for a CA manager's
-- approval, made through the issuer's domain-joined relay after trstctl's own
-- approval. Projections of adcs.request.decision_queued (which consumes the
-- operation approval) and adcs.request.decided (the relay's checked report).
-- A decision that has not been decided reads its relay job's state.
CREATE TABLE IF NOT EXISTS adcs_request_decisions (
    tenant_id            uuid        NOT NULL,
    id                   uuid        NOT NULL,
    issuer_id            text        NOT NULL,
    ca_config            text        NOT NULL,
    request_id           integer     NOT NULL CHECK (request_id > 0),
    decision             text        NOT NULL CHECK (decision IN ('approve', 'deny')),
    relay_agent_id       text        NOT NULL,
    reason               text        NOT NULL DEFAULT '',
    approval_request_id  uuid        NOT NULL,
    requested_by         text        NOT NULL,
    decided              boolean     NOT NULL DEFAULT false,
    disposition          text        NOT NULL DEFAULT '',
    serial               text        NOT NULL DEFAULT '',
    queued_at            timestamptz NOT NULL,
    decided_at           timestamptz,
    event_sequence       bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS adcs_request_decisions_issuer_idx ON adcs_request_decisions (tenant_id, issuer_id, queued_at DESC);
ALTER TABLE adcs_request_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE adcs_request_decisions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS adcs_request_decisions_isolation ON adcs_request_decisions;
CREATE POLICY adcs_request_decisions_isolation ON adcs_request_decisions
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON adcs_request_decisions TO trstctl_app;
