-- AUD-97: a retained outbox key can collide with a later immutable event that
-- describes a different receiver command. The old command remains authoritative
-- and byte-for-byte immutable; this tenant-scoped projection makes the refused
-- newer command visible without crash-looping the whole control plane.
CREATE TABLE IF NOT EXISTS outbox_reconciliation_conflicts (
    id                              text NOT NULL,
    tenant_id                       uuid NOT NULL,
    source_event_id                 text NOT NULL,
    source_event_sequence           bigint NOT NULL CHECK (source_event_sequence > 0),
    source_event_type               text NOT NULL,
    idempotency_key                 text NOT NULL,
    existing_outbox_id              bigint NOT NULL,
    existing_destination            text NOT NULL,
    existing_effect_lane            text NOT NULL,
    existing_payload_sha256         text NOT NULL CHECK (length(existing_payload_sha256) = 64),
    existing_required_agent_role    text NOT NULL DEFAULT '',
    existing_required_agent_id      text NOT NULL DEFAULT '',
    candidate_destination           text NOT NULL,
    candidate_effect_lane           text NOT NULL,
    candidate_payload_sha256        text NOT NULL CHECK (length(candidate_payload_sha256) = 64),
    candidate_required_agent_role   text NOT NULL DEFAULT '',
    candidate_required_agent_id     text NOT NULL DEFAULT '',
    reason                          text NOT NULL,
    status                          text NOT NULL CHECK (status IN ('quarantined')),
    detected_at                     timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, source_event_id)
);

ALTER TABLE outbox_reconciliation_conflicts ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_reconciliation_conflicts FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS outbox_reconciliation_conflicts_tenant_isolation ON outbox_reconciliation_conflicts;
CREATE POLICY outbox_reconciliation_conflicts_tenant_isolation ON outbox_reconciliation_conflicts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX IF NOT EXISTS outbox_reconciliation_conflicts_queue_idx
    ON outbox_reconciliation_conflicts (tenant_id, source_event_sequence DESC, id);

GRANT SELECT, INSERT, UPDATE, DELETE ON outbox_reconciliation_conflicts TO trstctl_app;
