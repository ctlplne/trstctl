-- Parked profile create/edit approval requests (dual control on profiles whose
-- spec carries requires_approval). Projected from the immutable
-- profile.edit_approval.* event family plus the profile.created/updated event
-- that closes a request, so a plane restart or another replica sees the same
-- parked request the requester was told about in its 202 (OPP-R09).
CREATE TABLE IF NOT EXISTS profile_edit_approvals (
    tenant_id               uuid NOT NULL,
    id                      uuid NOT NULL,
    name                    text NOT NULL,
    spec                    jsonb NOT NULL,
    requester               text NOT NULL,
    required_approvals      integer NOT NULL DEFAULT 1,
    approvals               jsonb NOT NULL DEFAULT '[]'::jsonb,
    state                   text NOT NULL DEFAULT 'awaiting_approval',
    profile_id              text NOT NULL DEFAULT '',
    restored_from_version   integer NOT NULL DEFAULT 0,
    restore_reason          text NOT NULL DEFAULT '',
    expected_active_version integer NOT NULL DEFAULT 0,
    created_at              timestamptz NOT NULL,
    expires_at              timestamptz NOT NULL,
    updated_at              timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CHECK (name <> ''),
    CHECK (requester <> ''),
    CHECK (required_approvals > 0),
    CHECK (expires_at > created_at),
    CHECK (state IN ('awaiting_approval', 'approved', 'issued', 'denied'))
);

ALTER TABLE profile_edit_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE profile_edit_approvals FORCE ROW LEVEL SECURITY;

CREATE POLICY profile_edit_approvals_isolation ON profile_edit_approvals
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX IF NOT EXISTS profile_edit_approvals_queue_idx
    ON profile_edit_approvals (tenant_id, state, created_at, id);

GRANT SELECT, INSERT, UPDATE, DELETE ON profile_edit_approvals TO trstctl_app;
