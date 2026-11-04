-- A265: renewal waves. A wave moves the renewal of some of an import's
-- certificates from the other product to trstctl: each row gets the one
-- identity trstctl keeps for it (its ID is derived from the import and row, so
-- a row never has two), bound to the deployment target the wave assigns it (a
-- target carries one active identity) and issued by trstctl. Rolling a wave
-- back (refused while an issuance or renewal is in flight) withdraws its queued
-- deploys, pauses each identity's renewal on its target and returns the rows
-- to watch-only.
-- Projections of switching.wave.cut_over and switching.wave.rolled_back.
CREATE TABLE IF NOT EXISTS switching_waves (
    tenant_id        uuid        NOT NULL,
    id               uuid        NOT NULL,
    import_id        uuid        NOT NULL,
    name             text        NOT NULL CHECK (length(name) <= 200),
    status           text        NOT NULL CHECK (status IN ('cut_over', 'rolled_back')),
    issuer_id        text        NOT NULL DEFAULT '',
    preview_digest   text        NOT NULL,
    rows_total       integer     NOT NULL CHECK (rows_total > 0),
    created_by       text        NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL,
    rolled_back_at   timestamptz,
    rolled_back_by   text        NOT NULL DEFAULT '',
    rollback_reason  text        NOT NULL DEFAULT '',
    event_sequence   bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, import_id) REFERENCES switching_imports (tenant_id, id)
);
CREATE TABLE IF NOT EXISTS switching_wave_rows (
    tenant_id             uuid    NOT NULL,
    wave_id               uuid    NOT NULL,
    import_id             uuid    NOT NULL,
    row_number            integer NOT NULL CHECK (row_number > 0),
    identity_id           uuid    NOT NULL,
    target_id             uuid    NOT NULL,
    imported_fingerprint  text    NOT NULL,
    live                  boolean NOT NULL DEFAULT true,
    event_sequence        bigint  NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, wave_id, row_number),
    FOREIGN KEY (tenant_id, wave_id) REFERENCES switching_waves (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS switching_wave_rows_live_idx ON switching_wave_rows (tenant_id, import_id, row_number) WHERE live;
ALTER TABLE switching_waves ENABLE ROW LEVEL SECURITY;
ALTER TABLE switching_waves FORCE ROW LEVEL SECURITY;
ALTER TABLE switching_wave_rows ENABLE ROW LEVEL SECURITY;
ALTER TABLE switching_wave_rows FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS switching_waves_isolation ON switching_waves;
CREATE POLICY switching_waves_isolation ON switching_waves
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
DROP POLICY IF EXISTS switching_wave_rows_isolation ON switching_wave_rows;
CREATE POLICY switching_wave_rows_isolation ON switching_wave_rows
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON switching_waves, switching_wave_rows TO trstctl_app;
