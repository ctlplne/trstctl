-- 0145_operation_approval_authority.sql -- AUD-77 exact, event-sourced approval authority.
--
-- The older issuance_approval_* tables identify a grant only by
-- (tenant, resource, action).  That tuple cannot distinguish two later attempts
-- to perform the same action, and therefore behaves like a standing permission.
-- These tables are the read model for approval.requested / approval.decided and
-- for the approval-use embedded in the event that performs the authorized
-- operation.  The immutable request id + intent digest is the authority.

CREATE TABLE IF NOT EXISTS operation_approval_requests (
    tenant_id          uuid NOT NULL,
    id                 uuid NOT NULL,
    intent_digest      text NOT NULL,
    resource_kind      text NOT NULL,
    resource_id        text NOT NULL,
    resource_name      text NOT NULL DEFAULT '',
    action             text NOT NULL,
    requester          text NOT NULL,
    from_state         text NOT NULL DEFAULT '',
    to_state           text NOT NULL DEFAULT '',
    target_version     bigint NOT NULL DEFAULT 0,
    reason             text NOT NULL DEFAULT '',
    evidence_refs      jsonb NOT NULL DEFAULT '[]'::jsonb,
    required_approvals integer NOT NULL,
    status             text NOT NULL DEFAULT 'pending',
    created_at         timestamptz NOT NULL,
    expires_at         timestamptz NOT NULL,
    updated_at         timestamptz NOT NULL,
    consumed_at        timestamptz,
    consumed_event_id  uuid,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, id, intent_digest),
    CHECK (requester <> ''),
    CHECK (required_approvals > 0),
    CHECK (expires_at > created_at),
    CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'superseded', 'consumed')),
    CHECK ((status = 'consumed') = (consumed_at IS NOT NULL AND consumed_event_id IS NOT NULL))
);

ALTER TABLE operation_approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE operation_approval_requests FORCE ROW LEVEL SECURITY;

CREATE POLICY operation_approval_requests_isolation ON operation_approval_requests
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX IF NOT EXISTS operation_approval_requests_queue_idx
    ON operation_approval_requests (tenant_id, status, created_at DESC, id);

CREATE INDEX IF NOT EXISTS operation_approval_requests_intent_idx
    ON operation_approval_requests
       (tenant_id, resource_kind, resource_id, action, requester, target_version);

GRANT SELECT, INSERT, UPDATE, DELETE ON operation_approval_requests TO trstctl_app;

CREATE TABLE IF NOT EXISTS operation_approval_decisions (
    tenant_id      uuid NOT NULL,
    request_id     uuid NOT NULL,
    intent_digest  text NOT NULL,
    approver       text NOT NULL,
    decision       text NOT NULL,
    reason         text NOT NULL DEFAULT '',
    event_id       uuid NOT NULL,
    decided_at     timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, request_id, approver, decision),
    UNIQUE (tenant_id, event_id),
    FOREIGN KEY (tenant_id, request_id, intent_digest)
        REFERENCES operation_approval_requests (tenant_id, id, intent_digest)
        ON DELETE CASCADE,
    CHECK (approver <> ''),
    CHECK (decision IN ('approve', 'deny'))
);

ALTER TABLE operation_approval_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE operation_approval_decisions FORCE ROW LEVEL SECURITY;

CREATE POLICY operation_approval_decisions_isolation ON operation_approval_decisions
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX IF NOT EXISTS operation_approval_decisions_request_idx
    ON operation_approval_decisions (tenant_id, request_id, decided_at, approver);

GRANT SELECT, INSERT, UPDATE, DELETE ON operation_approval_decisions TO trstctl_app;
