-- MSP-9: the devices an RMM lists under each customer's mapped organization,
-- the customer's agent each one maps to (installed through the RMM, or the
-- one agent of the same host name), the agent health last reported back to
-- the RMM, and the agent action last requested through it (action_event_id
-- names the request, so an outcome or a retried delivery applies only to the
-- request still in flight). One row per
-- customer, RMM target and device. The table is the projection of
-- provider.rmm_device.observed / .action_requested / .action_recorded and
-- rebuilds from the event log.
CREATE TABLE IF NOT EXISTS provider_rmm_devices (
    tenant_id      uuid        NOT NULL,
    target_id      text        NOT NULL CHECK (target_id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    device_id      text        NOT NULL CHECK (length(device_id) BETWEEN 1 AND 128),
    device_name    text        NOT NULL DEFAULT '' CHECK (length(device_name) <= 255),
    org_id         text        NOT NULL DEFAULT '' CHECK (length(org_id) <= 128),
    present        boolean     NOT NULL DEFAULT true,
    agent_id       text        NOT NULL DEFAULT '' CHECK (length(agent_id) <= 64),
    agent_match    text        NOT NULL DEFAULT '' CHECK (agent_match IN ('', 'installed', 'hostname')),
    health         text        NOT NULL DEFAULT '' CHECK (length(health) <= 255),
    action         text        NOT NULL DEFAULT '' CHECK (action IN ('', 'install', 'upgrade', 'remove')),
    action_status  text        NOT NULL DEFAULT '' CHECK (action_status IN ('', 'requested', 'done', 'failed')),
    action_reason  text        NOT NULL DEFAULT '' CHECK (length(action_reason) <= 2000),
    action_by      text        NOT NULL DEFAULT '' CHECK (length(action_by) <= 320),
    action_event_id text       NOT NULL DEFAULT '' CHECK (length(action_event_id) <= 64),
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    updated_at     timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, target_id, device_id)
);
CREATE INDEX IF NOT EXISTS provider_rmm_devices_recent_idx
    ON provider_rmm_devices (tenant_id, target_id, device_name);

ALTER TABLE provider_rmm_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_rmm_devices FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS provider_rmm_devices_tenant_isolation ON provider_rmm_devices;
CREATE POLICY provider_rmm_devices_tenant_isolation ON provider_rmm_devices
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON provider_rmm_devices TO trstctl_app;

COMMENT ON TABLE provider_rmm_devices IS
    'MSP-9: each customer''s RMM devices, the agent each maps to, the health reported back and the agent action last run through the RMM.';
