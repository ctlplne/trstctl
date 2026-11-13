-- MSP-3 part 2: the PSA service tickets a customer's alerts open, update and
-- close under its company in a Provider's PSA target. One row per customer,
-- target and alert subject (alert_key, e.g. certificate.expiry:<certificate>):
-- the first alert opens a ticket (generation 1), a later alert of the same
-- subject while it is open adds a note, and the ticket closes when the
-- subject's condition clears; a subject that comes back opens a new ticket
-- (the next generation). The row names the company the ticket was opened
-- under, so delivery can refuse work for a customer since remapped. The table
-- is the projection of provider.psa_ticket.requested / .recorded and rebuilds
-- from the event log.
CREATE TABLE IF NOT EXISTS provider_psa_tickets (
    tenant_id           uuid        NOT NULL,
    target_id           text        NOT NULL CHECK (target_id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    alert_key           text        NOT NULL CHECK (length(alert_key) BETWEEN 1 AND 400),
    generation          integer     NOT NULL CHECK (generation > 0),
    kind                text        NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
    status              text        NOT NULL CHECK (status IN ('opening', 'open', 'closing', 'closed', 'failed')),
    external_company_id text        NOT NULL CHECK (length(external_company_id) BETWEEN 1 AND 128),
    external_ticket_id  text        NOT NULL DEFAULT '' CHECK (length(external_ticket_id) <= 128),
    summary             text        NOT NULL DEFAULT '' CHECK (length(summary) <= 200),
    notes               integer     NOT NULL DEFAULT 0 CHECK (notes >= 0),
    reason              text        NOT NULL DEFAULT '' CHECK (length(reason) <= 2000),
    last_alert_ref      text        NOT NULL DEFAULT '' CHECK (length(last_alert_ref) <= 300),
    opened_at           timestamptz,
    closed_at           timestamptz,
    event_sequence      bigint      NOT NULL CHECK (event_sequence > 0),
    updated_at          timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, target_id, alert_key)
);
CREATE INDEX IF NOT EXISTS provider_psa_tickets_recent_idx
    ON provider_psa_tickets (tenant_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS provider_psa_tickets_open_idx
    ON provider_psa_tickets (target_id, status) WHERE status IN ('opening', 'open');

ALTER TABLE provider_psa_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_psa_tickets FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS provider_psa_tickets_tenant_isolation ON provider_psa_tickets;
CREATE POLICY provider_psa_tickets_tenant_isolation ON provider_psa_tickets
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON provider_psa_tickets TO trstctl_app;

COMMENT ON TABLE provider_psa_tickets IS
    'MSP-3: PSA service tickets a customer''s alerts opened, updated and closed under its company in a Provider PSA target.';
