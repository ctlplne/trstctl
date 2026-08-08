-- AD CS certificate-database ingestion (epic F4).
--
-- The Web Enrollment transport can issue against an enterprise CA, but issuance
-- alone gives no lifecycle VISIBILITY: an operator cannot see what that CA has
-- issued, what is pending a CA manager's approval, and what was revoked, denied,
-- or failed. certutil reports all of it from the CA database; the domain-joined
-- relay collects those rows and the control plane ingests them here.
--
-- This table holds the SUMMARY per CA, not a copy of every certificate — the
-- certificate inventory already owns individual certs. What it adds is the
-- per-disposition breakdown the inventory cannot show, because a certificate
-- trstctl never issued and a request still pending approval are not inventory
-- rows at all. Per AN-1 every row carries tenant_id under row-level security,
-- and the summary is a projection of adcs.ca_database.ingested (AN-2).
CREATE TABLE adcs_ca_databases (
    tenant_id   uuid        NOT NULL,
    -- ca_config is certsrv's own "HOST\CA Name" identifier, the stable key an
    -- operator recognises. Text because it is Windows-shaped, not a UUID.
    ca_config   text        NOT NULL,
    -- Per-disposition counts. PENDING is kept distinct from FAILED and DENIED
    -- on purpose: a pending request shown as failed makes an operator resubmit
    -- instead of getting it approved. UNKNOWN is a disposition code this build
    -- did not recognise, never folded into failed. UNPARSED counts issued rows
    -- whose expiry could not be read — a visibility gap, so the ingest cannot
    -- claim coverage it does not have.
    issued      integer     NOT NULL,
    pending     integer     NOT NULL,
    revoked     integer     NOT NULL,
    denied      integer     NOT NULL,
    failed      integer     NOT NULL,
    unknown     integer     NOT NULL,
    unparsed    integer     NOT NULL,
    total       integer     NOT NULL,
    -- read counts the rows the relay actually collected this sweep, and
    -- rejected counts rows that would not parse (no request id, etc.). A sweep
    -- that read 0 is distinct from one that found a CA with no certificates.
    rows_read     integer   NOT NULL,
    rows_rejected integer   NOT NULL,
    -- source names who collected it (the relay's identifier), and last_error is
    -- the last collection failure, served not just logged — a relay failing for
    -- a week otherwise looks identical to a CA with nothing new.
    source        text        NOT NULL DEFAULT '',
    last_error    text        NOT NULL DEFAULT '',
    ingested_at   timestamptz NOT NULL,
    event_sequence bigint     NOT NULL,
    PRIMARY KEY (tenant_id, ca_config)
);

ALTER TABLE adcs_ca_databases ENABLE ROW LEVEL SECURITY;
ALTER TABLE adcs_ca_databases FORCE ROW LEVEL SECURITY;

CREATE POLICY adcs_ca_databases_isolation ON adcs_ca_databases
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- The console's default question is "which CAs have pending approvals", so the
-- index serves pending-first ordering within a tenant.
CREATE INDEX adcs_ca_databases_pending_idx
    ON adcs_ca_databases (tenant_id, pending DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON adcs_ca_databases TO trstctl_app;
