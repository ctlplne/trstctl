-- XREC remediation execution receipts. These rows are tenant-scoped audit
-- evidence for the write-scoped remediation connector: delivered, denied by
-- operation-class grant, or failed pending retry.

CREATE TABLE xrec_remediation_receipts (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       uuid   NOT NULL,
    plan_id         text   NOT NULL,
    witness_id      text   NOT NULL,
    witness_hash    text   NOT NULL,
    authority_id    text   NOT NULL,
    record_key      jsonb  NOT NULL,
    operation       text   NOT NULL,
    connector       text   NOT NULL,
    status          text   NOT NULL,
    reason          text   NOT NULL,
    detail          text   NOT NULL DEFAULT '',
    idempotency_key text   NOT NULL,
    recorded_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT xrec_remediation_receipts_status
        CHECK (status IN ('delivered', 'denied', 'failed')),
    CONSTRAINT xrec_remediation_receipts_unique_key
        UNIQUE (tenant_id, idempotency_key)
);

ALTER TABLE xrec_remediation_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE xrec_remediation_receipts FORCE ROW LEVEL SECURITY;

CREATE POLICY xrec_remediation_receipts_isolation
    ON xrec_remediation_receipts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX xrec_remediation_receipts_plan_idx
    ON xrec_remediation_receipts (tenant_id, plan_id, recorded_at DESC);

GRANT SELECT, INSERT, UPDATE ON xrec_remediation_receipts TO trstctl_app;
