-- I5: the join between an MDM's device record and our SCEP transactions.
--
-- Today only a SCEP challenge gate exists. A certificate minted for a device
-- carries the subject the device asked for and nothing that ties it to the
-- device record an admin can actually see in Intune or Jamf — so "which device
-- is this certificate on" is a question nobody can answer without guessing from
-- a common name.
--
-- This table is a CORRELATION, not a copy of the MDM. It holds the identifiers
-- needed to join and the last thing the MDM said, and nothing else: duplicating
-- device inventory would create a second, staler source of truth about devices
-- that somebody would eventually trust.

CREATE TABLE IF NOT EXISTS mdm_device_correlations (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid NOT NULL,
    -- Which MDM: 'intune' or 'jamf'. Kept distinct rather than normalised to
    -- "the MDM" because an estate can run both, and a device present in one is
    -- not evidence about the other.
    mdm            text NOT NULL,
    -- The MDM's own device id. This is the identifier an admin can paste into
    -- their MDM console, which is the whole point of correlating.
    mdm_device_id  text NOT NULL,
    device_name    text NOT NULL DEFAULT '',
    serial_number  text NOT NULL DEFAULT '',
    -- The SCEP transaction this correlation was derived from. Without it a
    -- device with two enrollments cannot be told apart from two devices.
    transaction_id text NOT NULL DEFAULT '',
    -- The certificate we minted, when we know it.
    identity_id    uuid,
    -- What the MDM last said about the profile, verbatim in our vocabulary:
    -- 'ok' | 'failed' | 'unknown'. 'unknown' is NOT 'failed': an MDM we could
    -- not reach tells us nothing about the device, and recording that as a
    -- failure would send somebody to re-push a profile that is already there.
    install_state  text NOT NULL DEFAULT 'unknown',
    install_detail text NOT NULL DEFAULT '',
    -- When the MDM last told us. NULL means never observed, which is distinct
    -- from observed long ago — an operator deciding whether to trust a stale
    -- answer needs to tell those apart.
    observed_at    timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- One correlation per (mdm, device, transaction). A device that re-enrolls gets
-- a new row rather than overwriting the old one, so a failed enrollment stays
-- visible after a successful retry — that history is what an operator needs to
-- see a device that keeps failing.
CREATE UNIQUE INDEX IF NOT EXISTS mdm_device_correlations_key
    ON mdm_device_correlations (tenant_id, mdm, mdm_device_id, transaction_id);

-- AN-1: every table carries tenant_id and every query filters on it.
ALTER TABLE mdm_device_correlations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_device_correlations FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS mdm_device_correlations_tenant_isolation ON mdm_device_correlations;
CREATE POLICY mdm_device_correlations_tenant_isolation ON mdm_device_correlations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- The device view looks up by MDM device id; the failure queue looks up by
-- install state. Both are indexed rather than the whole table.
CREATE INDEX IF NOT EXISTS mdm_device_correlations_device_idx
    ON mdm_device_correlations (tenant_id, mdm, mdm_device_id);
CREATE INDEX IF NOT EXISTS mdm_device_correlations_failed_idx
    ON mdm_device_correlations (tenant_id, updated_at DESC)
    WHERE install_state = 'failed';

GRANT SELECT, INSERT, UPDATE, DELETE ON mdm_device_correlations TO trstctl_app;
