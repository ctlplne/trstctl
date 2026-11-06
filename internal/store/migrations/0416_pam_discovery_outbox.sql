-- A267: source account reads follow a durable intent and independent worker.
ALTER TABLE pam_discovery_runs DROP CONSTRAINT pam_discovery_runs_status_check;
ALTER TABLE pam_discovery_runs ADD CONSTRAINT pam_discovery_runs_status_check CHECK(status IN ('queued','completed','failed'));
ALTER TABLE pam_discovery_runs ALTER COLUMN finished_at DROP NOT NULL;
ALTER TABLE pam_discovery_runs ADD COLUMN scan_intent jsonb;
ALTER TABLE pam_discovery_runs ADD COLUMN outbox_id bigint;
CREATE UNIQUE INDEX pam_discovery_runs_pending_source_idx ON pam_discovery_runs(tenant_id,provider_id) WHERE status='queued';
