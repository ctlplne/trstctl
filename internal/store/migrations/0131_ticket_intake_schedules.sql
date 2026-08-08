-- I3: ticket-driven issuance-request intake.
--
-- The request object has a real lifecycle and a POST anyone scoped can call —
-- but the epic's own words are "ticket-driven intake": the ticket a requester
-- already filed in the ITSM should BECOME the request, without a human
-- re-typing it into a second system. This schedule is the standing instruction
-- to read the ITSM for such tickets.
--
-- The FIELD MAPPING is explicit, never inferred: an intake that guessed which
-- ticket field holds the certificate subject would open requests for whatever
-- happened to be in a description column. A ticket missing the mapped subject
-- or profile is SKIPPED AND COUNTED, not guessed at.
--
-- sn_table is bounded by a CHECK to the request-shaped tables. Reading is not
-- writing, but an unbounded table name would let a schedule aim the intake
-- token at sys_user_password and call it a ticket queue.
CREATE TABLE IF NOT EXISTS ticket_intake_schedules (
    tenant_id           uuid        NOT NULL,
    system              text        NOT NULL,
    instance_url        text        NOT NULL,
    token_ref           text        NOT NULL,
    sn_table            text        NOT NULL,
    query               text        NOT NULL DEFAULT '',
    subject_field       text        NOT NULL,
    profile_field       text        NOT NULL,
    requester_field     text        NOT NULL DEFAULT '',
    justification_field text        NOT NULL DEFAULT '',
    interval_seconds    integer     NOT NULL,
    enabled             boolean     NOT NULL DEFAULT false,
    allow_private_endpoint boolean  NOT NULL DEFAULT false,
    private_egress_cidrs   text[],
    last_run_at         timestamptz,
    last_error          text        NOT NULL DEFAULT '',
    updated_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, system),
    CONSTRAINT ticket_intake_system_known CHECK (system IN ('servicenow')),
    CONSTRAINT ticket_intake_table_known CHECK (sn_table IN ('incident', 'sc_req_item', 'sc_request', 'change_request'))
);

ALTER TABLE ticket_intake_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE ticket_intake_schedules FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS ticket_intake_schedules_tenant_isolation ON ticket_intake_schedules;
CREATE POLICY ticket_intake_schedules_tenant_isolation ON ticket_intake_schedules
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON ticket_intake_schedules TO trstctl_app;

COMMENT ON TABLE ticket_intake_schedules IS
    'Per-tenant ITSM ticket intake for issuance requests (epic I3). Projection of ticket.intake.configured; last_run_at/last_error are the scheduler''s observations.';
