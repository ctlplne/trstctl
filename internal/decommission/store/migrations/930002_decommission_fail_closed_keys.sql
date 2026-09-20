-- SPDX-License-Identifier: BUSL-1.1

-- VDEC revoke-first state. A key enters fail-closed before destruction: new
-- protective use is refused, while decrypt-for-reprotection may continue. The
-- control-plane runtime writes this row in the same tenant-scoped transaction as
-- revocation outbox intents.

CREATE TABLE decommission_fail_closed_keys (
    tenant_id  uuid NOT NULL,
    key_id     text NOT NULL,
    job_id     text NOT NULL,
    reason     text NOT NULL DEFAULT '',
    state      text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, key_id),
    CONSTRAINT decommission_fail_closed_state_known
        CHECK (state = 'fail-closed')
);

CREATE INDEX decommission_fail_closed_keys_job
    ON decommission_fail_closed_keys (tenant_id, job_id);

ALTER TABLE decommission_fail_closed_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE decommission_fail_closed_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY decommission_fail_closed_keys_isolation ON decommission_fail_closed_keys
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON decommission_fail_closed_keys TO trstctl_app;
