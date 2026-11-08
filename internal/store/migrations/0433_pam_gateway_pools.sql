-- SPDX-License-Identifier: BUSL-1.1
-- A278: gateway pools. Every gateway in a pool serves the sessions of a target
-- bound to any of them; a session is owned by the one chosen when it starts.
-- A draining member takes no new sessions. Projected from
-- pam.gateway_pool.saved and pam.gateway_pool.deleted.
CREATE TABLE pam_gateway_pools (
 tenant_id uuid NOT NULL,
 name text NOT NULL,
 members jsonb NOT NULL CHECK (jsonb_typeof(members) = 'array'),
 revision bigint NOT NULL,
 saved_by text NOT NULL,
 saved_at timestamptz NOT NULL,
 deleted_at timestamptz,
 PRIMARY KEY (tenant_id, name)
);
ALTER TABLE pam_gateway_pools ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_gateway_pools FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_gateway_pools_isolation ON pam_gateway_pools
 USING(tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
 WITH CHECK(tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON pam_gateway_pools TO trstctl_app;
