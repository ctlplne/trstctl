-- N9: device check-ins asked of an MDM (Intune syncDevice, a Jamf Pro blank
-- push) through the MDM schedule's relay after trstctl's own approval.
-- Projections of mdm.device.check_in_queued (which consumes the operation
-- approval) and mdm.device.checked_in (the relay's checked report). A
-- check-in the MDM has not acknowledged reads its relay job's state.
CREATE TABLE IF NOT EXISTS mdm_device_check_ins (
    tenant_id            uuid        NOT NULL,
    id                   uuid        NOT NULL,
    mdm                  text        NOT NULL CHECK (mdm IN ('intune', 'jamf')),
    device_id            text        NOT NULL CHECK (device_id <> ''),
    device_name          text        NOT NULL DEFAULT '',
    relay_agent_id       text        NOT NULL,
    reason               text        NOT NULL DEFAULT '',
    approval_request_id  uuid        NOT NULL,
    requested_by         text        NOT NULL,
    checked_in           boolean     NOT NULL DEFAULT false,
    provider_status      integer     NOT NULL DEFAULT 0,
    queued_at            timestamptz NOT NULL,
    checked_in_at        timestamptz,
    event_sequence       bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS mdm_device_check_ins_mdm_idx ON mdm_device_check_ins (tenant_id, mdm, queued_at DESC);
ALTER TABLE mdm_device_check_ins ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_device_check_ins FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS mdm_device_check_ins_isolation ON mdm_device_check_ins;
CREATE POLICY mdm_device_check_ins_isolation ON mdm_device_check_ins
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON mdm_device_check_ins TO trstctl_app;
