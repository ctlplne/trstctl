-- Per-tenant rate-limit token buckets (R2.3): the PostgreSQL-backed limiter that
-- sheds load on the served routes, so one noisy tenant cannot exhaust the control
-- plane (AN-7 in the live path). Each row is one (tenant, bucket) token bucket:
-- `tokens` available at `updated_at`, refilled by elapsed time on the next take.
-- Per AN-1 the table carries tenant_id and is confined by row-level security; an
-- unset tenant GUC denies every row (fail closed).
CREATE TABLE rate_limits (
    tenant_id  uuid NOT NULL,
    bucket     text NOT NULL,
    tokens     double precision NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, bucket)
);

ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limits FORCE ROW LEVEL SECURITY;

CREATE POLICY rate_limits_isolation ON rate_limits
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE ON rate_limits TO trstctl_app;
