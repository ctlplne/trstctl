-- A208: a person's S3 legal hold on one archive object (a report artifact or an
-- audit archive segment under the tenant's prefix). The hold is set in the
-- bucket by the outbox and recorded applied only after it reads back; release
-- works the same way. A projection of the archive.legal_hold.* events and of a
-- report legal hold that also holds its object.
CREATE TABLE IF NOT EXISTS archive_legal_holds (
    tenant_id      uuid        NOT NULL,
    id             uuid        NOT NULL,
    object         text        NOT NULL CHECK (object <> '' AND length(object) <= 1024),
    reason         text        NOT NULL CHECK (length(reason) BETWEEN 1 AND 512),
    report_run_id  uuid,
    placed_by      text        NOT NULL DEFAULT '',
    placed_at      timestamptz NOT NULL,
    status         text        NOT NULL CHECK (status IN ('pending', 'applied', 'release_pending', 'released', 'failed')),
    status_detail  text        NOT NULL DEFAULT '',
    applied_at     timestamptz,
    released_at    timestamptz,
    updated_at     timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id)
);
-- One hold at a time per object: a new one starts after the last is released
-- or failed.
CREATE UNIQUE INDEX IF NOT EXISTS archive_legal_holds_one_active
    ON archive_legal_holds (tenant_id, object) WHERE status IN ('pending', 'applied', 'release_pending');
ALTER TABLE archive_legal_holds ENABLE ROW LEVEL SECURITY;
ALTER TABLE archive_legal_holds FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS archive_legal_holds_isolation ON archive_legal_holds;
CREATE POLICY archive_legal_holds_isolation ON archive_legal_holds
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON archive_legal_holds TO trstctl_app;
