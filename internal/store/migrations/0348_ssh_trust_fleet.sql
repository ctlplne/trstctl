-- A226: an additive SSH trust rollout and its exact reviewed host roster.
-- Both tables are event projections. An operator's evidence-only attestation
-- never writes these rows or claims that a host executed a change.
CREATE TABLE IF NOT EXISTS ssh_trust_fleet_rollouts (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 plan jsonb NOT NULL CHECK (jsonb_typeof(plan) = 'object'),
 plan_digest text NOT NULL CHECK (plan_digest ~ '^sha256:[0-9a-f]{64}$'),
 approval_request_id uuid NOT NULL,
 requester text NOT NULL CHECK (requester <> ''),
 created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL,
 event_sequence bigint NOT NULL CHECK (event_sequence > 0),
 PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS ssh_trust_fleet_rollouts_page ON ssh_trust_fleet_rollouts (tenant_id, created_at DESC, id DESC);
ALTER TABLE ssh_trust_fleet_rollouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssh_trust_fleet_rollouts FORCE ROW LEVEL SECURITY;
CREATE POLICY ssh_trust_fleet_rollouts_isolation ON ssh_trust_fleet_rollouts
 USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
 WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON ssh_trust_fleet_rollouts TO trstctl_app;

CREATE TABLE IF NOT EXISTS ssh_trust_fleet_hosts (
 tenant_id uuid NOT NULL,
 rollout_id uuid NOT NULL,
 agent_id uuid NOT NULL,
 position integer NOT NULL CHECK (position >= 0 AND position < 100),
 readiness_digest text NOT NULL DEFAULT '',
 state text NOT NULL CHECK (state IN ('queued','skipped','verified','failed','refused')),
 skip_reason text NOT NULL DEFAULT '',
 receipt jsonb CHECK (receipt IS NULL OR jsonb_typeof(receipt) = 'object'),
 receipt_event_id uuid,
 job_id bigint,
 attempt integer,
 checked_at timestamptz,
 event_sequence bigint NOT NULL CHECK (event_sequence > 0),
 PRIMARY KEY (tenant_id, rollout_id, agent_id),
 UNIQUE (tenant_id, rollout_id, position),
 FOREIGN KEY (tenant_id, rollout_id) REFERENCES ssh_trust_fleet_rollouts (tenant_id,id) ON DELETE CASCADE,
 CHECK ((state = 'skipped') = (skip_reason <> '')),
 CHECK ((receipt IS NULL) = (receipt_event_id IS NULL)),
 CHECK ((receipt IS NULL) = (job_id IS NULL)),
 CHECK ((receipt IS NULL) = (attempt IS NULL)),
 CHECK ((receipt IS NULL) = (checked_at IS NULL)),
 CHECK (job_id IS NULL OR job_id > 0),
 CHECK (attempt IS NULL OR attempt > 0)
);
CREATE INDEX IF NOT EXISTS ssh_trust_fleet_hosts_agent ON ssh_trust_fleet_hosts (tenant_id, agent_id);
ALTER TABLE ssh_trust_fleet_hosts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssh_trust_fleet_hosts FORCE ROW LEVEL SECURITY;
CREATE POLICY ssh_trust_fleet_hosts_isolation ON ssh_trust_fleet_hosts
 USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
 WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON ssh_trust_fleet_hosts TO trstctl_app;
