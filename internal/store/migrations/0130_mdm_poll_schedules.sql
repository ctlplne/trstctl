-- I5: the standing instruction to re-read an MDM.
--
-- The correlation machinery — parsers, endpoint builders, the event, the
-- served routes — existed end to end with NOTHING calling it: the table the
-- console reads was written only by tests. This schedule is the missing
-- producer, one row per (tenant, mdm) because an estate can run Intune and
-- Jamf side by side and a device present in one is not evidence about the
-- other.
--
-- token_ref is a REFERENCE (env: or secret://), never a token value. execution
-- and renewal_window_days are NULLABLE with nothing backfilled: NULL execution
-- means the control plane runs the poll, and a NULL window means the renewal
-- check uses its documented standard rather than a recorded operator choice.
CREATE TABLE IF NOT EXISTS mdm_poll_schedules (
    tenant_id           uuid        NOT NULL,
    mdm                 text        NOT NULL,
    base_url            text        NOT NULL,
    token_ref           text        NOT NULL,
    filter              text        NOT NULL DEFAULT '',
    interval_seconds    integer     NOT NULL,
    enabled             boolean     NOT NULL DEFAULT false,
    -- A control-plane poll of a PRIVATE MDM (an on-prem Jamf) needs the same
    -- two-sided grant discovery's cloud sources need: the schedule asks, and
    -- the CIDR list bounds exactly which private ranges may be dialled. Relay
    -- execution needs neither; the relay is already inside.
    allow_private_endpoint boolean NOT NULL DEFAULT false,
    private_egress_cidrs   text[],
    execution           text,
    renewal_window_days integer,
    last_run_at         timestamptz,
    last_error          text        NOT NULL DEFAULT '',
    updated_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, mdm),
    CONSTRAINT mdm_poll_schedules_mdm_known CHECK (mdm IN ('intune', 'jamf'))
);

ALTER TABLE mdm_poll_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_poll_schedules FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS mdm_poll_schedules_tenant_isolation ON mdm_poll_schedules;
CREATE POLICY mdm_poll_schedules_tenant_isolation ON mdm_poll_schedules
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON mdm_poll_schedules TO trstctl_app;

COMMENT ON TABLE mdm_poll_schedules IS
    'Per-tenant, per-MDM read schedule (epic I5). Projection of mdm.poll.configured; last_run_at/last_error are the scheduler''s own observations.';
