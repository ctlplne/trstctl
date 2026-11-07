-- SPDX-License-Identifier: BUSL-1.1
CREATE TABLE windows_local_account_rotations (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 agent_id uuid NOT NULL,
 account_sid text NOT NULL,
 intent jsonb NOT NULL,
 prepared_event_id text NOT NULL,
 prepared_at timestamptz NOT NULL,
 outbox_id bigint,
 observed_event_id text NOT NULL DEFAULT '',
 observation jsonb,
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX windows_local_account_rotation_host_idx ON windows_local_account_rotations(tenant_id,agent_id,account_sid,prepared_at DESC,id);
ALTER TABLE windows_local_account_rotations ENABLE ROW LEVEL SECURITY;
ALTER TABLE windows_local_account_rotations FORCE ROW LEVEL SECURITY;
CREATE POLICY windows_local_account_rotations_isolation ON windows_local_account_rotations
 USING(tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
 WITH CHECK(tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON windows_local_account_rotations TO trstctl_app;
