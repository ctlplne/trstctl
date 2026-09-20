-- SPDX-License-Identifier: BUSL-1.1
-- Asset-specific accountability is event-sourced. This table is only the
-- tenant-scoped current projection; the immutable ownership.assigned events
-- retain every prior decision and its attributed reason.

CREATE TABLE ownership_assignments (
    tenant_id uuid NOT NULL,
    inventory_id text NOT NULL,
    source text NOT NULL,
    owner_id uuid NOT NULL,
    assigned_at timestamptz NOT NULL,
    source_event_id text NOT NULL,
    last_event_seq bigint NOT NULL,
    PRIMARY KEY (tenant_id, inventory_id),
    CONSTRAINT ownership_assignments_inventory_id_bounds
        CHECK (char_length(inventory_id) BETWEEN 3 AND 1024),
    CONSTRAINT ownership_assignments_source_bounds
        CHECK (char_length(source) BETWEEN 1 AND 128),
    CONSTRAINT ownership_assignments_event_id_bounds
        CHECK (char_length(source_event_id) BETWEEN 1 AND 64),
    CONSTRAINT ownership_assignments_sequence_nonnegative CHECK (last_event_seq >= 0),
    CONSTRAINT ownership_assignments_owner_fk
        FOREIGN KEY (tenant_id, owner_id) REFERENCES owners (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE ownership_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE ownership_assignments FORCE ROW LEVEL SECURITY;

CREATE POLICY ownership_assignments_isolation ON ownership_assignments
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX ownership_assignments_owner_idx
    ON ownership_assignments (tenant_id, owner_id, inventory_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON ownership_assignments TO trstctl_app;

COMMENT ON TABLE ownership_assignments IS
    'Current event-derived asset ownership overrides. Immutable ownership.assigned events preserve decision history and attributed reasons.';
