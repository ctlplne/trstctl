-- SPDX-License-Identifier: BUSL-1.1
-- A276: brokered accounts whose owner is gone, or that sat unused past the
-- deployment's window, flagged with what an approved action did about them.
-- One row per account: its latest flag.
CREATE TABLE pam_account_flags (
 tenant_id uuid NOT NULL,
 target_type text NOT NULL,
 target_id text NOT NULL,
 reasons text[] NOT NULL,
 detail text NOT NULL DEFAULT '',
 owner_id text NOT NULL DEFAULT '',
 last_used_at timestamptz,
 flagged_at timestamptz NOT NULL,
 status text NOT NULL CHECK (status IN ('open', 'cleared', 'actioned')),
 cleared_at timestamptz,
 action text NOT NULL DEFAULT '' CHECK (action IN ('', 'reassign', 'rotate_disable')),
 action_owner_id text NOT NULL DEFAULT '',
 action_rotation_id text NOT NULL DEFAULT '',
 action_reason text NOT NULL DEFAULT '',
 approval_request_id text NOT NULL DEFAULT '',
 actioned_by text NOT NULL DEFAULT '',
 actioned_at timestamptz,
 PRIMARY KEY (tenant_id, target_type, target_id)
);
CREATE INDEX pam_account_flags_status_idx ON pam_account_flags(tenant_id, status, flagged_at DESC);
ALTER TABLE pam_account_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_account_flags FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_account_flags_isolation ON pam_account_flags
 USING(tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
 WITH CHECK(tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON pam_account_flags TO trstctl_app;
