-- SPDX-License-Identifier: BUSL-1.1

-- M2-L2: a tenant's misuse detection thresholds, the Enterprise governance
-- detector's policy, projected from misuse.policy.set (AN-2). A tenant with no
-- row is detected with the defaults (three days, 64 reads, four times, 14
-- days, 20 alerts an hour). Core schema, licensed projection, like
-- misuse_findings.
CREATE TABLE IF NOT EXISTS misuse_policies (
    tenant_id           uuid        PRIMARY KEY,
    normal_days         integer     NOT NULL CHECK (normal_days BETWEEN 1 AND 30),
    burst_floor         integer     NOT NULL CHECK (burst_floor BETWEEN 1 AND 100000),
    burst_factor        integer     NOT NULL CHECK (burst_factor BETWEEN 2 AND 100),
    burst_lookback_days integer     NOT NULL CHECK (burst_lookback_days BETWEEN 1 AND 90),
    hourly_alert_cap    integer     NOT NULL CHECK (hourly_alert_cap BETWEEN 1 AND 1000),
    set_by              text        NOT NULL DEFAULT '',
    updated_at          timestamptz NOT NULL,
    event_sequence      bigint      NOT NULL CHECK (event_sequence >= 0)
);
ALTER TABLE misuse_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE misuse_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS misuse_policies_isolation ON misuse_policies;
CREATE POLICY misuse_policies_isolation ON misuse_policies
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON misuse_policies TO trstctl_app;
