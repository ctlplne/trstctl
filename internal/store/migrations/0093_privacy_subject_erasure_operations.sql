-- Durable AN-5 receiver records for privacy subject erasure. This is independent
-- operational evidence recovered from the PostgreSQL backup, not a truncatable
-- read model: its source event may have moved from the live log into the signed
-- retention archive while a pending request still needs its canonical response.
-- The aggregate
-- privacy_subject_erasures row is keyed by subject and may be replaced by a
-- later operator action; this operation projection remains keyed by the opaque,
-- tenant-bound operation identity so a retry can recover its exact response
-- after idempotency-cache GC or live-event retention.

CREATE TABLE privacy_subject_erasure_operations (
    tenant_id        uuid NOT NULL,
    operation_id     text NOT NULL,
    request_binding  text NOT NULL,
    event_id         text NOT NULL,
    event_sequence   bigint NOT NULL CHECK (event_sequence > 0),
    subject_ref      text NOT NULL,
    requested_by_ref text NOT NULL DEFAULT '',
    reason           text NOT NULL DEFAULT '',
    selectors        jsonb NOT NULL DEFAULT '{}',
    counts           jsonb NOT NULL DEFAULT '{}',
    erased_at        timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    UNIQUE (tenant_id, event_id)
);

ALTER TABLE privacy_subject_erasure_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE privacy_subject_erasure_operations FORCE ROW LEVEL SECURITY;

CREATE POLICY privacy_subject_erasure_operations_isolation
    ON privacy_subject_erasure_operations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX privacy_subject_erasure_operations_erased_at_idx
    ON privacy_subject_erasure_operations (tenant_id, erased_at DESC, operation_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON privacy_subject_erasure_operations TO trstctl_app;
