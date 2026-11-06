-- A267: exact enrolled hosts and signed read-only native dependent inventory.
CREATE TABLE service_account_hosts (
 tenant_id uuid NOT NULL,
 account_id uuid NOT NULL,
 agent_id uuid NOT NULL,
 binding jsonb NOT NULL,
 revision bigint NOT NULL CHECK (revision > 0),
 enabled boolean NOT NULL,
 saved_by text NOT NULL,
 updated_at timestamptz NOT NULL,
 PRIMARY KEY (tenant_id, account_id, agent_id)
);
ALTER TABLE service_account_hosts ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_account_hosts FORCE ROW LEVEL SECURITY;
CREATE POLICY service_account_hosts_isolation ON service_account_hosts
 USING (tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
 WITH CHECK (tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON service_account_hosts TO trstctl_app;

CREATE TABLE service_account_host_scans (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 account_id uuid NOT NULL,
 agent_id uuid NOT NULL,
 intent jsonb NOT NULL,
 binding_digest text NOT NULL CHECK(binding_digest ~ '^[0-9a-f]{64}$'),
 status text NOT NULL CHECK(status IN ('queued','complete','partial','retrying','failed','superseded')),
 queued_by text NOT NULL,
 queued_at timestamptz NOT NULL,
 queued_event_id uuid NOT NULL,
 outbox_id bigint,
 report jsonb,
 report_digest text NOT NULL DEFAULT '',
 failure text NOT NULL DEFAULT '',
 service_count integer NOT NULL DEFAULT 0,
 task_count integer NOT NULL DEFAULT 0,
 pool_count integer NOT NULL DEFAULT 0,
 received_at timestamptz,
 observed_at timestamptz,
 receipt_job_id bigint,
 job_attempt integer,
 receipt_statement text NOT NULL DEFAULT '',
 receipt_signature text NOT NULL DEFAULT '',
 signer_fingerprint text NOT NULL DEFAULT '',
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX service_account_host_scans_binding_idx ON service_account_host_scans(tenant_id,account_id,agent_id,queued_at DESC,id);
ALTER TABLE service_account_host_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_account_host_scans FORCE ROW LEVEL SECURITY;
CREATE POLICY service_account_host_scans_isolation ON service_account_host_scans
 USING (tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
 WITH CHECK (tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON service_account_host_scans TO trstctl_app;
