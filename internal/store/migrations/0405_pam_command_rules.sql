-- A262: public command guardrails and the exact policy reviewed for a session.
-- Existing templates/sessions keep their previous behavior. Action decisions
-- are projected from immutable events; no credential, statement or Bind value
-- is a field of this read model.
ALTER TABLE pam_access_templates ADD COLUMN command_rules jsonb NOT NULL DEFAULT '[]'::jsonb
    CHECK (jsonb_typeof(command_rules) = 'array');
ALTER TABLE pam_sessions ADD COLUMN command_policy jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(command_policy) = 'object');
CREATE TABLE pam_command_actions (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    session_id uuid NOT NULL,
    job_id bigint NOT NULL CHECK (job_id > 0),
    attempt integer NOT NULL CHECK (attempt > 0),
    connection_id uuid NOT NULL,
    ordinal bigint NOT NULL CHECK (ordinal > 0),
    phase text NOT NULL,
    protocol text NOT NULL,
    rule_ids jsonb NOT NULL CHECK (jsonb_typeof(rule_ids) = 'array'),
    operations jsonb NOT NULL CHECK (jsonb_typeof(operations) = 'array'),
    policy_digest text NOT NULL,
    message_digest text NOT NULL,
    status text NOT NULL,
    reason text NOT NULL,
    decided_at timestamptz NOT NULL,
    observed_at timestamptz NOT NULL,
    review_expires_at timestamptz,
    source_event_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX pam_command_actions_session ON pam_command_actions (tenant_id, session_id, observed_at DESC, id DESC);
ALTER TABLE pam_command_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_command_actions FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_command_actions_isolation ON pam_command_actions
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_command_actions TO trstctl_app;
