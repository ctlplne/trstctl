-- I2: a tenant's standing instruction to re-read ownership from its CMDB.
--
-- The acceptance says changes "reconcile on a schedule", and a schedule has to
-- be per tenant for the same reason discovery schedules are: the instance URL
-- and the credential are the tenant's, and a single process-wide poller would
-- either serve one tenant or leak one tenant's CMDB into another's ownership.
--
-- Modelled on discovery_schedules deliberately — same shape, same due-decision
-- style, same leader-only sweep — so there is one scheduling pattern in this
-- system rather than two that drift apart.

CREATE TABLE IF NOT EXISTS cmdb_reconcile_schedules (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         uuid NOT NULL,
    -- The ServiceNow instance to read. Validated against the operator's
    -- configured binding allow-list before it is ever dialled, so a tenant
    -- cannot point the control plane at an arbitrary host.
    instance_url      text NOT NULL,
    -- A reference such as env:TRSTCTL_SERVICENOW_TOKEN. Never the token itself:
    -- a credential in a table is a credential in every backup of that table.
    token_ref         text NOT NULL,
    -- The sysparm_query narrowing which CIs matter. Empty reads the default
    -- page, which is the honest default: an operator who has not said which
    -- CIs are certificates should get a small answer, not the whole CMDB.
    ci_query          text NOT NULL DEFAULT '',
    -- Reaching a ServiceNow instance inside a private network is the same
    -- decision the ticket writer already makes, gated by the same operator
    -- binding and the same egress:private permission. Mirrored rather than
    -- reinvented: a second rule for the same risk is a second rule to get wrong.
    allow_private_endpoint boolean NOT NULL DEFAULT false,
    interval_seconds  integer NOT NULL,
    enabled           boolean NOT NULL DEFAULT false,
    last_run_at       timestamptz,
    last_error        text NOT NULL DEFAULT '',
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

-- One standing schedule per tenant. A second row would mean two pollers racing
-- to reconcile the same owners, and whichever landed last would look like the
-- answer.
CREATE UNIQUE INDEX IF NOT EXISTS cmdb_reconcile_schedules_tenant_key
    ON cmdb_reconcile_schedules (tenant_id);

-- AN-1: every table carries tenant_id and every query filters on it.
ALTER TABLE cmdb_reconcile_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE cmdb_reconcile_schedules FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS cmdb_reconcile_schedules_tenant_isolation ON cmdb_reconcile_schedules;
CREATE POLICY cmdb_reconcile_schedules_tenant_isolation ON cmdb_reconcile_schedules
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON cmdb_reconcile_schedules TO trstctl_app;
