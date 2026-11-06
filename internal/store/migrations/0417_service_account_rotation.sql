-- Durable parent authority and exact native steps for service-account rotation.
CREATE TABLE service_account_rotations (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 intent jsonb NOT NULL,
 intent_digest text NOT NULL CHECK(intent_digest ~ '^[0-9a-f]{64}$'),
 command_id uuid NOT NULL,
 tenant_epoch text NOT NULL,
 directory_apply_started boolean NOT NULL DEFAULT false,
 directory_restored boolean NOT NULL DEFAULT false,
 direction text NOT NULL CHECK(direction IN ('forward','inverse')),
 actor text NOT NULL,
 failure text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id),
 UNIQUE(tenant_id,command_id)
);
ALTER TABLE service_account_rotations ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_account_rotations FORCE ROW LEVEL SECURITY;
CREATE POLICY service_account_rotations_isolation ON service_account_rotations
 USING(tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
 WITH CHECK(tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON service_account_rotations TO trstctl_app;

CREATE TABLE service_account_rotation_steps (
 tenant_id uuid NOT NULL,
 rotation_id uuid NOT NULL,
 step_id text NOT NULL CHECK(step_id ~ '^[0-9a-f]{32}$'),
 intent jsonb NOT NULL,
 direction text NOT NULL CHECK(direction IN ('forward','inverse')),
 status text NOT NULL CHECK(status IN ('queued','succeeded','failed','uncertain')),
 outbox_id bigint,
 report jsonb,
 receipt_job_id bigint,
 job_attempt integer,
 receipt_statement text NOT NULL DEFAULT '',
 receipt_signature text NOT NULL DEFAULT '',
 signer_fingerprint text NOT NULL DEFAULT '',
 queued_at timestamptz NOT NULL,
 received_at timestamptz,
 PRIMARY KEY(tenant_id,rotation_id,step_id)
);
ALTER TABLE service_account_rotation_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_account_rotation_steps FORCE ROW LEVEL SECURITY;
CREATE POLICY service_account_rotation_steps_isolation ON service_account_rotation_steps
 USING(tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
 WITH CHECK(tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON service_account_rotation_steps TO trstctl_app;

ALTER TABLE secret_static_rotation_commands ADD COLUMN dependent_change_id uuid;
CREATE UNIQUE INDEX secret_static_rotation_dependent_parent_idx
 ON secret_static_rotation_commands(tenant_id,dependent_change_id) WHERE dependent_change_id IS NOT NULL;

-- A reviewed rotation reads the canonical signed observation, not a rewritten SQL report.
ALTER TABLE service_account_host_scans ADD COLUMN observed_event_id text CHECK(observed_event_id ~ '^[A-Za-z0-9._:-]{1,128}$');
