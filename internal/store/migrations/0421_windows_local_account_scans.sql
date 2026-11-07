-- SPDX-License-Identifier: BUSL-1.1
CREATE TABLE windows_local_account_scans (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 agent_id uuid NOT NULL,
 intent jsonb NOT NULL,
 status text NOT NULL CHECK (status IN ('queued','complete','failed','retrying')),
 queued_by text NOT NULL,
 queued_at timestamptz NOT NULL,
 queued_event_id uuid NOT NULL,
 outbox_id bigint,
 report jsonb,
 report_digest text NOT NULL DEFAULT '',
 failure text NOT NULL DEFAULT '',
 received_at timestamptz,
 receipt_job_id bigint,
 job_attempt integer,
 receipt_statement text NOT NULL DEFAULT '',
 receipt_signature text NOT NULL DEFAULT '',
 signer_fingerprint text NOT NULL DEFAULT '',
 observed_event_id uuid,
 PRIMARY KEY (tenant_id,id)
);
CREATE INDEX windows_local_account_scans_host_idx ON windows_local_account_scans(tenant_id,agent_id,queued_at DESC,id);
ALTER TABLE windows_local_account_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE windows_local_account_scans FORCE ROW LEVEL SECURITY;
CREATE POLICY windows_local_account_scans_isolation ON windows_local_account_scans
 USING (tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
 WITH CHECK (tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON windows_local_account_scans TO trstctl_app;
