-- N9-L2: a check-in wave asks an MDM to have every device of a renewal wave
-- check in under one approval. The wave row records the approval it spent and
-- how many devices it named; each device's check-in is an mdm_device_check_ins
-- row with the same approval, so a wave's progress reads from them.
-- Projection of mdm.device.check_in_wave_queued.
CREATE TABLE IF NOT EXISTS mdm_check_in_waves (
    tenant_id            uuid        NOT NULL,
    id                   uuid        NOT NULL,
    mdm                  text        NOT NULL CHECK (mdm IN ('intune', 'jamf')),
    relay_agent_id       text        NOT NULL,
    reason               text        NOT NULL DEFAULT '',
    approval_request_id  uuid        NOT NULL,
    requested_by         text        NOT NULL,
    device_count         integer     NOT NULL CHECK (device_count > 0),
    queued_at            timestamptz NOT NULL,
    event_sequence       bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS mdm_check_in_waves_mdm_idx ON mdm_check_in_waves (tenant_id, mdm, queued_at DESC);
ALTER TABLE mdm_check_in_waves ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_check_in_waves FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS mdm_check_in_waves_isolation ON mdm_check_in_waves;
CREATE POLICY mdm_check_in_waves_isolation ON mdm_check_in_waves
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON mdm_check_in_waves TO trstctl_app;
