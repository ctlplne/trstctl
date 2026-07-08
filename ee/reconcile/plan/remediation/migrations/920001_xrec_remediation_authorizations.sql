-- XREC remediation authorizations (ee/reconcile/plan/remediation) — proprietary
-- Enterprise/Provider. Version 920001 is in the reserved extension high band
-- (>= 900000) and does not collide with PCAS (900xxx) or AGID (910xxx).

CREATE TABLE xrec_remediation_authorizations (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       uuid   NOT NULL,
    event_type      text   NOT NULL DEFAULT 'xrec.remediation.authorized',
    plan_id         text   NOT NULL,
    plan_hash       text   NOT NULL,
    witness_id      text   NOT NULL,
    witness_hash    text   NOT NULL,
    authority_id    text   NOT NULL,
    record_key      jsonb  NOT NULL,
    operation       text   NOT NULL,
    signer_authorization bytea NOT NULL,
    idempotency_key text   NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT xrec_remediation_authorizations_event_type
        CHECK (event_type = 'xrec.remediation.authorized'),
    CONSTRAINT xrec_remediation_authorizations_unique_key
        UNIQUE (tenant_id, idempotency_key)
);

ALTER TABLE xrec_remediation_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE xrec_remediation_authorizations FORCE ROW LEVEL SECURITY;

CREATE POLICY xrec_remediation_authorizations_isolation
    ON xrec_remediation_authorizations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX xrec_remediation_authorizations_plan_idx
    ON xrec_remediation_authorizations (tenant_id, plan_id, created_at DESC);

GRANT SELECT, INSERT, UPDATE ON xrec_remediation_authorizations TO trstctl_app;
