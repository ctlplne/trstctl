-- SPDX-License-Identifier: LicenseRef-trstctl-EE

-- Event-derived CA-key retirement state. The immutable request/refusal/record
-- events are authoritative; this table makes the current result cheap to serve.
-- Every row is tenant-owned and FORCE RLS denies an unset tenant context.

CREATE TABLE decommission_retirements (
    tenant_id          uuid   NOT NULL,
    key_id             text   NOT NULL,
    command_event_id   text   NOT NULL,
    status             text   NOT NULL,
    final_epoch        bigint NOT NULL,
    ledger_position    bigint NOT NULL,
    refusal_record     bytea,
    destruction_record bytea,
    record_event_id    text   NOT NULL DEFAULT '',
    updated_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, key_id),
    UNIQUE (tenant_id, command_event_id),
    CONSTRAINT decommission_retirements_status_known
        CHECK (status IN ('pending', 'refused', 'destroyed')),
    CONSTRAINT decommission_retirements_final_epoch_positive
        CHECK (final_epoch > 0),
    CONSTRAINT decommission_retirements_ledger_position_positive
        CHECK (ledger_position > 0),
    CONSTRAINT decommission_retirements_terminal_shape
        CHECK (
            (status = 'pending' AND refusal_record IS NULL AND destruction_record IS NULL AND record_event_id = '') OR
            (status = 'refused' AND refusal_record IS NOT NULL AND destruction_record IS NULL AND record_event_id = '') OR
            (status = 'destroyed' AND refusal_record IS NULL AND destruction_record IS NOT NULL AND record_event_id <> '')
        )
);

CREATE INDEX decommission_retirements_status
    ON decommission_retirements (tenant_id, status, updated_at);

ALTER TABLE decommission_retirements ENABLE ROW LEVEL SECURITY;
ALTER TABLE decommission_retirements FORCE ROW LEVEL SECURITY;

CREATE POLICY decommission_retirements_isolation ON decommission_retirements
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON decommission_retirements TO trstctl_app;
