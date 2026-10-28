-- A216: the re-key ceremony the CA calendar drafted for an authority entering
-- the configured rollover band, or why none could be opened. A projection of
-- ca.rollover.drafted; one row per authority, the newest draft.
CREATE TABLE IF NOT EXISTS ca_rollover_drafts (
    tenant_id           uuid        NOT NULL,
    authority_id        uuid        NOT NULL,
    band_months         integer     NOT NULL CHECK (band_months >= 0),
    not_after           timestamptz NOT NULL,
    ceremony_id         text        NOT NULL DEFAULT '',
    preview_fingerprint text        NOT NULL DEFAULT '',
    reason              text        NOT NULL DEFAULT '',
    ttl_seconds         bigint      NOT NULL DEFAULT 0,
    not_drafted_reason  text        NOT NULL DEFAULT '',
    drafted_at          timestamptz NOT NULL,
    event_sequence      bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, authority_id),
    CHECK ((ceremony_id <> '') <> (not_drafted_reason <> ''))
);
ALTER TABLE ca_rollover_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ca_rollover_drafts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ca_rollover_drafts_isolation ON ca_rollover_drafts;
CREATE POLICY ca_rollover_drafts_isolation ON ca_rollover_drafts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON ca_rollover_drafts TO trstctl_app;
