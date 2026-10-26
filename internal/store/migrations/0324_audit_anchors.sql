-- A147: continuous audit anchoring at a known cadence.
--
-- A projection of the audit.anchored events the licensed anchoring worker
-- appends to each tenant's own audit log: the tenant's full audit chain head
-- through a tenant-local record, timestamped by the TSA. The event is the
-- source of truth (the offline verifier reads it from the exported records);
-- this table serves the anchoring status and the anchor log, and rebuilds from
-- the event log.
CREATE TABLE IF NOT EXISTS audit_anchors (
    tenant_id        uuid        NOT NULL,
    event_id         text        NOT NULL CHECK (event_id <> ''),
    through_sequence bigint      NOT NULL CHECK (through_sequence > 0),
    chain_head       text        NOT NULL CHECK (chain_head ~ '^[0-9a-f]{64}$'),
    anchored_at      timestamptz NOT NULL,
    token_serial     numeric(20) NOT NULL CHECK (token_serial >= 0),
    token_sha256     text        NOT NULL CHECK (token_sha256 ~ '^[0-9a-f]{64}$'),
    cadence_seconds  bigint      NOT NULL CHECK (cadence_seconds > 0),
    event_sequence   bigint      NOT NULL CHECK (event_sequence > 0),
    recorded_at      timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, event_id)
);
CREATE INDEX IF NOT EXISTS audit_anchors_by_time
    ON audit_anchors (tenant_id, anchored_at DESC);
CREATE INDEX IF NOT EXISTS audit_anchors_by_event_sequence
    ON audit_anchors (tenant_id, event_sequence);
ALTER TABLE audit_anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_anchors FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_anchors_isolation ON audit_anchors;
CREATE POLICY audit_anchors_isolation ON audit_anchors
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_anchors TO trstctl_app;
