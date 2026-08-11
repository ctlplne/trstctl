-- A privacy history rewrite crosses two durable systems: PostgreSQL recovery
-- fences and one JetStream generation cutover.  This tenant-scoped preparation
-- is the crash bridge between them.  It contains only one-way references,
-- stable row/event selectors, and already-sanitized event metadata -- never the
-- raw subject being erased.
--
-- The preparation is inserted in the same PostgreSQL transaction that captures
-- selectors and removes/pseudonymizes recoverable command copies.  The final
-- privacy.subject.erased projection deletes it in the same transaction that
-- writes the durable erasure operation.  Therefore either side of a process
-- crash has one unambiguous recovery instruction.

CREATE TABLE privacy_subject_erasure_preparations (
    tenant_id        UUID        NOT NULL,
    operation_id     TEXT        NOT NULL,
    request_binding  TEXT        NOT NULL,
    event_id         TEXT        NOT NULL,
    rewrite_operation_id TEXT    NOT NULL,
    target_generation    TEXT    NOT NULL,
    subject_ref      CHAR(64)    NOT NULL,
    requested_by_ref TEXT        NOT NULL DEFAULT '',
    reason           TEXT        NOT NULL DEFAULT '',
    selectors        JSONB       NOT NULL DEFAULT '{}',
    counts           JSONB       NOT NULL DEFAULT '{}',
    event_actor      JSONB,
    recovery_fences  JSONB       NOT NULL DEFAULT '[]',
    scheduler_dispositions JSONB NOT NULL DEFAULT '[]',
    erased_at        TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, operation_id),
    UNIQUE (tenant_id, event_id),
    UNIQUE (tenant_id, subject_ref),
    CHECK (length(btrim(operation_id)) > 0),
    CHECK (length(btrim(request_binding)) > 0),
    CHECK (length(btrim(event_id)) > 0),
    CHECK (length(btrim(rewrite_operation_id)) > 0),
    CHECK (length(btrim(target_generation)) > 0),
    CHECK (subject_ref ~ '^[0-9a-f]{64}$'),
    CHECK (requested_by_ref = '' OR requested_by_ref ~ '^[0-9a-f]{64}$'),
    CHECK (jsonb_typeof(selectors) = 'object'),
    CHECK (jsonb_typeof(counts) = 'object'),
    CHECK (event_actor IS NULL OR (
        jsonb_typeof(event_actor) = 'object'
        AND event_actor ? 'subject'
        AND jsonb_typeof(event_actor->'subject') = 'string'
        AND length(btrim(event_actor->>'subject')) > 0
        AND (NOT event_actor ? 'roles' OR jsonb_typeof(event_actor->'roles') = 'array')
    )),
    CHECK (jsonb_typeof(recovery_fences) = 'array'),
    CHECK (jsonb_typeof(scheduler_dispositions) = 'array')
);

ALTER TABLE privacy_subject_erasure_preparations ENABLE ROW LEVEL SECURITY;
ALTER TABLE privacy_subject_erasure_preparations FORCE ROW LEVEL SECURITY;

CREATE POLICY privacy_subject_erasure_preparations_isolation
    ON privacy_subject_erasure_preparations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON privacy_subject_erasure_preparations TO trstctl_app;

COMMENT ON TABLE privacy_subject_erasure_preparations IS
    'Non-PII crash bridge for an in-progress privacy event-history generation rewrite; active rows block recovery publication until the deterministic erasure event projects.';

COMMENT ON COLUMN privacy_subject_erasure_preparations.recovery_fences IS
    'Stable event IDs plus deleted/pseudonymized dispositions captured before history cutover; contains no command payload or raw subject.';

COMMENT ON COLUMN privacy_subject_erasure_preparations.scheduler_dispositions IS
    'Bounded non-PII scheduler tick/command authority references plus closed privacy-erased dispositions captured in the same preparation transaction.';
