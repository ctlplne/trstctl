-- OD-9 (A257-L1): a standing approval lets an access bundle's runs have their
-- privileged session requests for one delegated account, as one role,
-- approved without a reviewer until it expires or is revoked. It is never on
-- by default: an administrator who may approve access grants each one for
-- one bundle, one account and one role, with an expiry. Sessions opened
-- under it are recorded and revocable like any other, and revoking it ends
-- the live sessions it approved. The table is the projection of
-- access.bundle_standing_approval.granted, .revoked and .used, and rebuilds
-- from the event log.
CREATE TABLE IF NOT EXISTS access_bundle_standing_approvals (
    tenant_id        uuid        NOT NULL,
    id               uuid        NOT NULL,
    bundle_id        uuid        NOT NULL,
    target_type      text        NOT NULL CHECK (target_type <> '' AND length(target_type) <= 64),
    target_id        text        NOT NULL CHECK (target_id <> '' AND length(target_id) <= 200),
    role             text        NOT NULL CHECK (role <> '' AND length(role) <= 128),
    reason           text        NOT NULL CHECK (length(btrim(reason)) > 0 AND length(reason) <= 500),
    granted_by       text        NOT NULL DEFAULT '',
    granted_at       timestamptz NOT NULL,
    expires_at       timestamptz NOT NULL,
    revoked_at       timestamptz,
    revoked_by       text        NOT NULL DEFAULT '',
    revoke_reason    text        NOT NULL DEFAULT '',
    approvals        bigint      NOT NULL DEFAULT 0 CHECK (approvals >= 0),
    last_approved_at timestamptz,
    event_sequence   bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, bundle_id) REFERENCES access_bundles (tenant_id, id),
    CHECK (expires_at > granted_at)
);
CREATE INDEX IF NOT EXISTS access_bundle_standing_approvals_account_idx
    ON access_bundle_standing_approvals (tenant_id, bundle_id, target_type, target_id, role);
ALTER TABLE access_bundle_standing_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_bundle_standing_approvals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS access_bundle_standing_approvals_isolation ON access_bundle_standing_approvals;
CREATE POLICY access_bundle_standing_approvals_isolation ON access_bundle_standing_approvals
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON access_bundle_standing_approvals TO trstctl_app;

-- The bundle's activity records each standing approval granted, revoked and
-- used. Existing rows hold the six earlier actions, which the check still
-- admits.
ALTER TABLE access_bundle_activity
    DROP CONSTRAINT IF EXISTS access_bundle_activity_action_check;

ALTER TABLE access_bundle_activity
    ADD CONSTRAINT access_bundle_activity_action_check
        CHECK (action IN ('saved', 'deleted', 'granted', 'ungranted', 'run_issued', 'run_revoked',
                          'standing_approval_granted', 'standing_approval_revoked', 'standing_approval_used')) NOT VALID;

ALTER TABLE access_bundle_activity
    VALIDATE CONSTRAINT access_bundle_activity_action_check;
