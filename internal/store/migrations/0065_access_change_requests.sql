-- Access-change requests and approval / PR change-management workflow (CAP-GOV-05).
--
-- These tables are read-model projections of access.change_request.* events. The
-- rows carry only non-secret change metadata: NHI identifiers, resource/entitlement
-- labels, PR/change references, reviewer decisions, and evidence references.
CREATE TABLE access_change_requests (
    tenant_id          uuid        NOT NULL,
    id                 uuid        NOT NULL,
    requested_action   text        NOT NULL,
    requester_subject  text        NOT NULL,
    nhi_id             text        NOT NULL,
    nhi_kind           text        NOT NULL,
    display_name       text        NOT NULL,
    owner_ref          text        NOT NULL DEFAULT '',
    resource           text        NOT NULL,
    entitlement        text        NOT NULL,
    change_ref         text        NOT NULL,
    change_system      text        NOT NULL DEFAULT 'external',
    change_url         text        NOT NULL DEFAULT '',
    risk               text        NOT NULL DEFAULT 'medium',
    reason             text        NOT NULL,
    evidence_refs      text[]      NOT NULL DEFAULT '{}',
    status             text        NOT NULL DEFAULT 'pending',
    required_approvals integer     NOT NULL DEFAULT 1,
    approval_count     integer     NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    completed_at       timestamptz,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT access_change_requests_status_chk
        CHECK (status IN ('pending', 'approved', 'denied')),
    CONSTRAINT access_change_requests_action_chk
        CHECK (requested_action IN ('grant', 'modify', 'revoke', 'rotate', 'deploy', 'break_glass')),
    CONSTRAINT access_change_requests_required_chk
        CHECK (requested_action <> '' AND requester_subject <> '' AND nhi_id <> '' AND nhi_kind <> '' AND display_name <> '' AND resource <> '' AND entitlement <> '' AND change_ref <> '' AND reason <> ''),
    CONSTRAINT access_change_requests_approval_count_chk
        CHECK (required_approvals >= 1 AND required_approvals <= 5 AND approval_count >= 0 AND approval_count <= required_approvals)
);

CREATE TABLE access_change_request_decisions (
    tenant_id              uuid        NOT NULL,
    request_id             uuid        NOT NULL,
    approver_subject       text        NOT NULL,
    decision               text        NOT NULL,
    reason                 text        NOT NULL DEFAULT '',
    decision_evidence_refs text[]      NOT NULL DEFAULT '{}',
    decided_at             timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, request_id, approver_subject),
    CONSTRAINT access_change_request_decisions_request_fk
        FOREIGN KEY (tenant_id, request_id)
        REFERENCES access_change_requests (tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT access_change_request_decisions_decision_chk
        CHECK (decision IN ('approved', 'denied')),
    CONSTRAINT access_change_request_decisions_required_chk
        CHECK (approver_subject <> '')
);

CREATE INDEX access_change_requests_tenant_status_idx
    ON access_change_requests (tenant_id, status, id);

CREATE INDEX access_change_requests_tenant_change_ref_idx
    ON access_change_requests (tenant_id, change_ref);

CREATE INDEX access_change_request_decisions_request_idx
    ON access_change_request_decisions (tenant_id, request_id, decided_at);

ALTER TABLE access_change_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_change_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE access_change_request_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_change_request_decisions FORCE ROW LEVEL SECURITY;

CREATE POLICY access_change_requests_isolation ON access_change_requests
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE POLICY access_change_request_decisions_isolation ON access_change_request_decisions
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON access_change_requests TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON access_change_request_decisions TO trstctl_app;
