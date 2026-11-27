-- SPDX-License-Identifier: BUSL-1.1

-- A receipt commits with an event's core read-model write. Catch-up can use
-- the exact event identity to distinguish a completed inline projection from
-- an event that still needs to change the read model.
CREATE TABLE projection_applied_event_receipts (
    tenant_id UUID NOT NULL,
    event_id TEXT NOT NULL,
    event_sequence BIGINT NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, event_id)
);

ALTER TABLE projection_applied_event_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE projection_applied_event_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY projection_applied_event_receipts_isolation ON projection_applied_event_receipts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, DELETE ON projection_applied_event_receipts TO trstctl_app;
