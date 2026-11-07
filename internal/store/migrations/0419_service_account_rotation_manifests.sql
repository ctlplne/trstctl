-- A267: immutable bounded review pages; no native mutation is queued by these rows.
CREATE TABLE service_account_rotation_manifests (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 header jsonb NOT NULL,
 header_digest text NOT NULL CHECK(header_digest ~ '^[0-9a-f]{64}$'),
 actor text NOT NULL,
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 page_count bigint NOT NULL DEFAULT 0 CHECK(page_count >= 0),
 entry_count bigint NOT NULL DEFAULT 0 CHECK(entry_count >= 0),
 host_count bigint NOT NULL DEFAULT 0 CHECK(host_count >= 0),
 seal jsonb,
 PRIMARY KEY(tenant_id,id)
);
ALTER TABLE service_account_rotation_manifests ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_account_rotation_manifests FORCE ROW LEVEL SECURITY;
CREATE POLICY service_account_rotation_manifests_isolation ON service_account_rotation_manifests
 USING(tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
 WITH CHECK(tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON service_account_rotation_manifests TO trstctl_app;

CREATE TABLE service_account_rotation_manifest_pages (
 tenant_id uuid NOT NULL,
 manifest_id uuid NOT NULL,
 page_number bigint NOT NULL CHECK(page_number >= 0),
 page jsonb NOT NULL,
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 PRIMARY KEY(tenant_id,manifest_id,page_number)
);
ALTER TABLE service_account_rotation_manifest_pages ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_account_rotation_manifest_pages FORCE ROW LEVEL SECURITY;
CREATE POLICY service_account_rotation_manifest_pages_isolation ON service_account_rotation_manifest_pages
 USING(tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
 WITH CHECK(tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON service_account_rotation_manifest_pages TO trstctl_app;

CREATE TABLE service_account_rotation_manifest_hosts (
 tenant_id uuid NOT NULL,
 manifest_id uuid NOT NULL,
 agent_id uuid NOT NULL,
 host jsonb NOT NULL,
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 PRIMARY KEY(tenant_id,manifest_id,agent_id)
);
ALTER TABLE service_account_rotation_manifest_hosts ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_account_rotation_manifest_hosts FORCE ROW LEVEL SECURITY;
CREATE POLICY service_account_rotation_manifest_hosts_isolation ON service_account_rotation_manifest_hosts
 USING(tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
 WITH CHECK(tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON service_account_rotation_manifest_hosts TO trstctl_app;

CREATE TABLE service_account_rotation_manifest_entries (
 tenant_id uuid NOT NULL,
 manifest_id uuid NOT NULL,
 ordinal bigint NOT NULL CHECK(ordinal >= 0),
 page_number bigint NOT NULL CHECK(page_number >= 0),
 agent_id uuid NOT NULL,
 ref_digest text NOT NULL CHECK(ref_digest ~ '^[0-9a-f]{64}$'),
 entry jsonb NOT NULL,
 PRIMARY KEY(tenant_id,manifest_id,ordinal),
 UNIQUE(tenant_id,manifest_id,ref_digest)
);
CREATE INDEX service_account_rotation_manifest_host_entries_idx
 ON service_account_rotation_manifest_entries(tenant_id,manifest_id,agent_id,ordinal);
ALTER TABLE service_account_rotation_manifest_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_account_rotation_manifest_entries FORCE ROW LEVEL SECURITY;
CREATE POLICY service_account_rotation_manifest_entries_isolation ON service_account_rotation_manifest_entries
 USING(tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
 WITH CHECK(tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON service_account_rotation_manifest_entries TO trstctl_app;
