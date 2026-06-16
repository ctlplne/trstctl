-- 0029_issuance_approvals.sql — served dual-control for privileged issuance/revoke
-- (EXC-WIRE-03; closes SEC-002, the served half of RED-004).
--
-- The RA model and the internal/approval state machine encode "a requester cannot
-- self-issue" and "two distinct approvers are required", but until now they were
-- library-only: no served route recorded or required an approval. This is the
-- served, RLS-isolated read model the gate consults — mirroring the proven
-- ca_key_ceremonies / ca_ceremony_approvals m-of-n pattern (PKIGOV-003/006), but for
-- the issue/revoke lifecycle transition rather than a CA key ceremony.
--
-- A row in issuance_approval_requests records a pending privileged action on a
-- resource (an identity) and the requester who opened it (for opener != approver
-- separation of duties). issuance_approvals records each DISTINCT approver's
-- approval (the PRIMARY KEY makes one approver idempotent). The gate allows the
-- transition only once the distinct-approver count reaches the required threshold,
-- and the store rejects an approval by the requester themselves (self-approval),
-- exactly as the ceremony approval store does.
--
-- Per AN-1 every row carries tenant_id and isolation is enforced by row-level
-- security that is ENABLED and FORCE-d (the table owner must not bypass it), with a
-- WITH CHECK matching the USING clause so writes are confined too (TENANT-008).

CREATE TABLE IF NOT EXISTS issuance_approval_requests (
    tenant_id  uuid NOT NULL,
    resource   text NOT NULL,                 -- the identity (or other credential) the action targets
    action     text NOT NULL,                 -- 'issue' | 'revoke' (the privileged action)
    requester  text NOT NULL DEFAULT '',      -- principal who opened the request (for opener != approver SoD)
    required   integer NOT NULL DEFAULT 2,    -- distinct approvals required (dual control)
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, resource, action)
);

ALTER TABLE issuance_approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE issuance_approval_requests FORCE  ROW LEVEL SECURITY;

CREATE POLICY issuance_approval_requests_isolation ON issuance_approval_requests
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON issuance_approval_requests TO trstctl_app;

-- One distinct approver's approval of a (resource, action). The PRIMARY KEY makes a
-- re-approval by the same approver idempotent, so the distinct-approver count is the
-- number of rows.
CREATE TABLE IF NOT EXISTS issuance_approvals (
    tenant_id   uuid NOT NULL,
    resource    text NOT NULL,
    action      text NOT NULL,
    approver    text NOT NULL,
    approved_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, resource, action, approver),
    FOREIGN KEY (tenant_id, resource, action)
        REFERENCES issuance_approval_requests (tenant_id, resource, action) ON DELETE CASCADE
);

ALTER TABLE issuance_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE issuance_approvals FORCE  ROW LEVEL SECURITY;

CREATE POLICY issuance_approvals_isolation ON issuance_approvals
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX IF NOT EXISTS issuance_approvals_tenant_resource_idx
    ON issuance_approvals (tenant_id, resource, action);

GRANT SELECT, INSERT, UPDATE, DELETE ON issuance_approvals TO trstctl_app;
