-- A265: switching kit. An import reads another certificate-management
-- product's export (described by format, never by product), maps every row to
-- exactly one outcome, and records the certificates and owners it can, so the
-- two products can run side by side. Projections of switching.import.started,
-- switching.import.rows_recorded, switching.import.rows_applied and
-- switching.import.completed. A row carries the export's metadata and, when
-- the export had it, the public certificate; never a key.
CREATE TABLE IF NOT EXISTS switching_imports (
    tenant_id       uuid        NOT NULL,
    id              uuid        NOT NULL,
    name            text        NOT NULL CHECK (length(name) <= 200),
    format          text        NOT NULL,
    preview_digest  text        NOT NULL,
    rows_total      integer     NOT NULL CHECK (rows_total >= 0),
    counts          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    gap_counts      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    rows_recorded   integer     NOT NULL DEFAULT 0 CHECK (rows_recorded >= 0),
    rows_applied    integer     NOT NULL DEFAULT 0 CHECK (rows_applied >= 0),
    status          text        NOT NULL CHECK (status IN ('recording', 'completed')),
    created_by      text        NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL,
    completed_at    timestamptz,
    -- The endpoint watch (switching.import.watch_requested / watch_observed):
    -- round n checks every mapped row's endpoints; watch_pending counts the
    -- rows round n has not observed yet. Private destinations are reached
    -- only through the CIDRs the operator granted.
    watch_round          integer     NOT NULL DEFAULT 0 CHECK (watch_round >= 0),
    watch_pending        integer     NOT NULL DEFAULT 0 CHECK (watch_pending >= 0),
    watch_allow_private  boolean     NOT NULL DEFAULT false,
    watch_private_cidrs  text[]      NOT NULL DEFAULT '{}',
    watch_requested_at   timestamptz,
    watch_requested_by   text        NOT NULL DEFAULT '',
    event_sequence  bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE IF NOT EXISTS switching_import_rows (
    tenant_id           uuid        NOT NULL,
    import_id           uuid        NOT NULL,
    row_number          integer     NOT NULL CHECK (row_number > 0),
    outcome             text        NOT NULL CHECK (outcome IN ('mapped', 'mapped_with_gaps', 'duplicate', 'unparseable', 'expired')),
    gaps                text[]      NOT NULL DEFAULT '{}',
    reason              text        NOT NULL DEFAULT '',
    duplicate_of        integer,
    fingerprint         text        NOT NULL DEFAULT '',
    common_name         text        NOT NULL DEFAULT '',
    sans                text[]      NOT NULL DEFAULT '{}',
    key_algorithm       text        NOT NULL DEFAULT '',
    serial              text        NOT NULL DEFAULT '',
    issuer              text        NOT NULL DEFAULT '',
    not_after           timestamptz,
    folder              text        NOT NULL DEFAULT '',
    profile             text        NOT NULL DEFAULT '',
    application         text        NOT NULL DEFAULT '',
    owner_email         text        NOT NULL DEFAULT '',
    endpoints           text[]      NOT NULL DEFAULT '{}',
    -- certificate_der: the public certificate when the export carried it,
    -- recorded with the certificate so its revocation details can be read.
    certificate_der     bytea,
    certificate_id      uuid,
    owner_id            uuid,
    -- linked: the row's certificate was already in the inventory, so applying
    -- linked the row to it and left the certificate as it was.
    linked              boolean     NOT NULL DEFAULT false,
    applied_at          timestamptz,
    -- What the row's endpoints served at the last watch round.
    watch_round         integer     NOT NULL DEFAULT 0 CHECK (watch_round >= 0),
    watch_status        text        NOT NULL DEFAULT '' CHECK (watch_status IN ('', 'matched', 'serves_other', 'unreachable',
                                    'no_endpoint', 'serves_trstctl', 'renewed_by_other_product')),
    watch_endpoint      text        NOT NULL DEFAULT '',
    served_fingerprint  text        NOT NULL DEFAULT '',
    watch_detail        text        NOT NULL DEFAULT '',
    watched_at          timestamptz,
    event_sequence      bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, import_id, row_number),
    FOREIGN KEY (tenant_id, import_id) REFERENCES switching_imports (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS switching_imports_work_idx ON switching_imports (tenant_id)
    WHERE status = 'recording' OR watch_pending > 0 OR watch_round > 0;
CREATE INDEX IF NOT EXISTS switching_import_rows_fingerprint_idx ON switching_import_rows (tenant_id, fingerprint);
CREATE INDEX IF NOT EXISTS switching_import_rows_pending_idx ON switching_import_rows (tenant_id, import_id)
    WHERE applied_at IS NULL AND outcome IN ('mapped', 'mapped_with_gaps');
ALTER TABLE switching_imports ENABLE ROW LEVEL SECURITY;
ALTER TABLE switching_imports FORCE ROW LEVEL SECURITY;
ALTER TABLE switching_import_rows ENABLE ROW LEVEL SECURITY;
ALTER TABLE switching_import_rows FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS switching_imports_isolation ON switching_imports;
CREATE POLICY switching_imports_isolation ON switching_imports
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
DROP POLICY IF EXISTS switching_import_rows_isolation ON switching_import_rows;
CREATE POLICY switching_import_rows_isolation ON switching_import_rows
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON switching_imports, switching_import_rows TO trstctl_app;
