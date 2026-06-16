-- Idempotency keys (AN-5): every state-changing operation is recorded here under
-- its Idempotency-Key, so a replay returns the original result instead of
-- executing again and concurrent identical requests collapse to a single effect.
-- Per AN-1 the table carries tenant_id and is confined by row-level security.
CREATE TABLE idempotency_keys (
    tenant_id    uuid NOT NULL,
    key          text NOT NULL,
    status       text NOT NULL DEFAULT 'pending',
    result       bytea,
    created_at   timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    PRIMARY KEY (tenant_id, key)
);

-- AN-1: isolation is enforced by row-level security, not application code. Unlike
-- the tenants read model (written by system projections), these rows are written
-- under RLS by the orchestrator, so the policy needs WITH CHECK as well as USING.
ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_keys FORCE ROW LEVEL SECURITY;

-- A session may touch only its current tenant's keys; an unset GUC is NULL, so
-- the policy denies every row (fail closed).
CREATE POLICY idempotency_keys_isolation ON idempotency_keys
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE ON idempotency_keys TO trstctl_app;
