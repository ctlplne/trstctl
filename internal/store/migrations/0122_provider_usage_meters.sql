-- L2: durable per-customer usage metering.
--
-- Metering was in memory. That does not merely lose usage on restart — it loses
-- it SILENTLY: a provider pulls a number, invoices from it, and never learns the
-- number was short. The customer is under-billed and the revenue disappears into
-- a process restart nobody correlated.
--
-- These carry tenant_id, so AN-1 applies and the doctor's ISO-1 probe is right
-- to demand ENABLE + FORCE row level security. The instinct to put billing
-- "outside the tenant fence" was wrong: a table with tenant_id that skips RLS is
-- exactly the shape of an isolation hole, and the correct way to stop a tenant
-- editing the meter that bills them is the GRANT, not the absence of a policy.
--
-- So: RLS confines every access to one tenant, and trstctl_app gets SELECT only.
-- A tenant may see what they are billed for; nothing reachable by a tenant can
-- change it.

CREATE TABLE IF NOT EXISTS provider_usage_meters (
    tenant_id    uuid NOT NULL,
    meter        text NOT NULL,
    -- period_start is the bucket. Counters accumulate into it; gauges overwrite
    -- it, which is why kind is stored: adding a gauge would double-count a
    -- value that was never a delta.
    period_start timestamptz NOT NULL,
    kind         text NOT NULL,
    value        bigint NOT NULL DEFAULT 0,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, meter, period_start)
);

-- observed_from / observed_to are what makes evidence signable. MaySign refuses
-- a period the store cannot prove it covered end to end, so the store has to
-- record what it actually watched rather than letting a gap look like a zero.
CREATE TABLE IF NOT EXISTS provider_usage_coverage (
    tenant_id     uuid PRIMARY KEY,
    observed_from timestamptz NOT NULL,
    observed_to   timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE provider_usage_meters ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_usage_meters FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_usage_meters_tenant_isolation ON provider_usage_meters;
CREATE POLICY provider_usage_meters_tenant_isolation ON provider_usage_meters
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

ALTER TABLE provider_usage_coverage ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_usage_coverage FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_usage_coverage_tenant_isolation ON provider_usage_coverage;
CREATE POLICY provider_usage_coverage_tenant_isolation ON provider_usage_coverage
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- Full DML to trstctl_app, exactly like every other tenant-scoped table.
--
-- A first draft granted SELECT only, reasoning that a tenant must not be able to
-- edit the meter that bills them. That was wrong twice over: trstctl_app is the
-- SERVER's role, not a tenant's — no tenant has direct SQL — so the grant does
-- not protect anything a tenant could otherwise reach, and it blocked the
-- recorder's own writes. What confines this data is RLS plus the served API
-- surface, which exposes no route that lets a tenant alter its own usage.
GRANT SELECT, INSERT, UPDATE, DELETE ON provider_usage_meters TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON provider_usage_coverage TO trstctl_app;
