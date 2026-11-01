-- P6: a leaked-secret finding moved into the native secret store. The CLI
-- re-finds the value in the operator's checkout, stores it as a native secret
-- and links the finding to that secret's name and version; no value is kept
-- here. residue lists the history commits that still held the value when it
-- moved (locations only). consumer_read_* records the first read of a version
-- newer than the moved one: a consumer picked up the rotated value. The leader
-- closes the finding only after a rotation, that read, and a completed scan
-- that no longer sees it. A projection of discovery.finding.secret_moved and
-- discovery.finding.secret_consumer_read.
CREATE TABLE IF NOT EXISTS discovery_finding_secret_moves (
    tenant_id             uuid        NOT NULL,
    finding_id            uuid        NOT NULL,
    secret_name           text        NOT NULL CHECK (secret_name <> ''),
    secret_version        integer     NOT NULL CHECK (secret_version > 0),
    moved_by              text        NOT NULL DEFAULT '',
    moved_at              timestamptz NOT NULL,
    residue               jsonb       NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(residue) = 'array' AND jsonb_array_length(residue) <= 100),
    consumer_read_version integer,
    consumer_reader       text        NOT NULL DEFAULT '',
    consumer_read_at      timestamptz,
    event_sequence        bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, finding_id),
    CONSTRAINT discovery_finding_secret_moves_read_is_newer CHECK (
        (consumer_read_at IS NULL AND consumer_read_version IS NULL)
        OR (consumer_read_at IS NOT NULL AND consumer_read_version > secret_version))
);
CREATE INDEX IF NOT EXISTS discovery_finding_secret_moves_awaiting_read
    ON discovery_finding_secret_moves (tenant_id, secret_name) WHERE consumer_read_at IS NULL;
ALTER TABLE discovery_finding_secret_moves ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_finding_secret_moves FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS discovery_finding_secret_moves_isolation ON discovery_finding_secret_moves;
CREATE POLICY discovery_finding_secret_moves_isolation ON discovery_finding_secret_moves
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON discovery_finding_secret_moves TO trstctl_app;
