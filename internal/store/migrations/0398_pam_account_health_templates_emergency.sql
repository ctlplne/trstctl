-- A258: credential health, access templates and emergency access.
--
-- The health of each brokered account's stored credential — whether the
-- credential a PAM target's provider holds still signs in — projected from
-- pam.account.health_checked. A row carries the last check's outcome class and
-- when the account began failing, never the credential or its digest.
CREATE TABLE IF NOT EXISTS pam_account_health (
    tenant_id uuid NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    provider_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('healthy', 'rejected', 'expired', 'locked', 'unreachable', 'error', 'not_supported')),
    attempts integer NOT NULL DEFAULT 0,
    checked_at timestamptz NOT NULL,
    failing_since timestamptz,
    PRIMARY KEY (tenant_id, target_type, target_id)
);

ALTER TABLE pam_account_health ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_account_health FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_account_health_isolation ON pam_account_health
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_account_health TO trstctl_app;

-- A258: reusable access templates. A session request may name one: its reason
-- is recorded, its approvals raise the review quorum and its maximum length
-- bounds the session. Projected from pam.template.saved and
-- pam.template.deleted; a deleted template stays, marked, for the sessions
-- that named it. A live name is unique by the broker's check, not an index:
-- a projection must never fail on replay, and sessions name templates by ID.
CREATE TABLE IF NOT EXISTS pam_access_templates (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    name text NOT NULL,
    reason text NOT NULL,
    required_approvals integer NOT NULL CHECK (required_approvals BETWEEN 1 AND 10),
    max_ttl_seconds integer NOT NULL CHECK (max_ttl_seconds > 0),
    revision bigint NOT NULL,
    saved_by text NOT NULL,
    saved_at timestamptz NOT NULL,
    deleted_at timestamptz,
    PRIMARY KEY (tenant_id, id)
);
ALTER TABLE pam_access_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_access_templates FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_access_templates_isolation ON pam_access_templates
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_access_templates TO trstctl_app;

-- A258: the named responders who may open emergency access, projected from
-- pam.emergency.responders_set (the whole list each time).
CREATE TABLE IF NOT EXISTS pam_emergency_responders (
    tenant_id uuid NOT NULL,
    subject text NOT NULL,
    set_by text NOT NULL,
    set_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, subject)
);
ALTER TABLE pam_emergency_responders ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_emergency_responders FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_emergency_responders_isolation ON pam_emergency_responders
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_emergency_responders TO trstctl_app;

-- A258: emergency access grants — a session a named responder opened without
-- waiting for approval — with the post-incident review each one requires.
-- Projected from pam.emergency.opened and pam.emergency.reviewed.
CREATE TABLE IF NOT EXISTS pam_emergency_grants (
    tenant_id uuid NOT NULL,
    session_id uuid NOT NULL,
    responder text NOT NULL,
    reason text NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    role text NOT NULL,
    opened_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    review_status text NOT NULL CHECK (review_status IN ('pending', 'reviewed')),
    reviewer text NOT NULL DEFAULT '',
    review_outcome text NOT NULL DEFAULT '',
    review_notes text NOT NULL DEFAULT '',
    reviewed_at timestamptz,
    PRIMARY KEY (tenant_id, session_id)
);
CREATE INDEX IF NOT EXISTS pam_emergency_grants_pending_idx
    ON pam_emergency_grants (tenant_id, opened_at) WHERE review_status = 'pending';
ALTER TABLE pam_emergency_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_emergency_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_emergency_grants_isolation ON pam_emergency_grants
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_emergency_grants TO trstctl_app;
