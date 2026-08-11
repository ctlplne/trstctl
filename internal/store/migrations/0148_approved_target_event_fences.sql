-- AUD-77: JetStream's duplicate-ID memory is finite, while an approval grant is
-- durable. A process can therefore receive an Append ACK and lose its SQL
-- transaction, then retry after the broker forgot the ID. Keep the exact first
-- approved target event in PostgreSQL before Append so every retry projects (or,
-- if the log was restored without the event, republishes) the same command.
--
-- This is independent command/recovery state, not a mutable read model. The
-- target projector deletes the matching row in the same transaction that applies
-- the effect. A surviving row means publication/projection still needs repair.

CREATE TABLE approved_target_event_fences (
    tenant_id          UUID        NOT NULL,
    target_kind        TEXT        NOT NULL,
    command_key        TEXT        NOT NULL,
    request_binding    CHAR(64)    NOT NULL,
    approval_request_id UUID       NOT NULL,
    approval_intent_digest TEXT    NOT NULL,
    event_id           UUID        NOT NULL,
    event_type         TEXT        NOT NULL,
    schema_version     INTEGER     NOT NULL,
    event_time         TIMESTAMPTZ NOT NULL,
    event_actor        JSONB,
    event_payload      BYTEA       NOT NULL,
    payload_sha256     CHAR(64)    NOT NULL,
    semantic_sha256    CHAR(64)    NOT NULL,
    approval           JSONB       NOT NULL,
    claim_state        TEXT        NOT NULL DEFAULT 'claimed',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, target_kind, command_key),
    UNIQUE (tenant_id, event_id),
    CHECK (target_kind IN ('ephemeral_certificate', 'code_signing_command')),
    CHECK (length(btrim(command_key)) > 0),
    CHECK (request_binding ~ '^[0-9a-f]{64}$'),
    CHECK (approval_intent_digest ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (length(btrim(event_type)) > 0),
    CHECK (schema_version > 0),
    CHECK (octet_length(event_payload) > 0),
    CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (semantic_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (claim_state = 'claimed')
);

ALTER TABLE approved_target_event_fences ENABLE ROW LEVEL SECURITY;
ALTER TABLE approved_target_event_fences FORCE ROW LEVEL SECURITY;

CREATE POLICY approved_target_event_fences_isolation
    ON approved_target_event_fences
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON approved_target_event_fences TO trstctl_app;

COMMENT ON TABLE approved_target_event_fences IS
    'Independent first-approved-target command fence; exact grant consumption and canonical event bytes commit before broker publication and the target projector retires the row.';

COMMENT ON COLUMN approved_target_event_fences.semantic_sha256 IS
    'Canonical normalized command SHA, except a privacy-rewritten legacy schema-v2 code-signing fence retains its atomically rewritten historical-compatibility SHA until retirement so its pre-PostgreSQL nanosecond timestamp remains provable.';

-- Persist the immutable source/capability identity on the code-signing read row.
-- Without it, a retained duplicate carrying the same ciphertext but a different
-- approval could consume a second grant while leaving the first command in place.
-- NULL is the honest legacy-v1 shape.
ALTER TABLE code_signing_operations
    ADD COLUMN source_event_id UUID,
    ADD COLUMN approval_request_id UUID,
    ADD COLUMN approval_intent_digest TEXT,
    ADD COLUMN command_semantic_sha256 CHAR(64);

ALTER TABLE code_signing_operations
    ADD CONSTRAINT code_signing_approved_source_complete CHECK (
        (source_event_id IS NULL AND approval_request_id IS NULL AND
         approval_intent_digest IS NULL AND command_semantic_sha256 IS NULL)
        OR
        (source_event_id IS NOT NULL AND approval_request_id IS NOT NULL AND
         approval_intent_digest ~ '^sha256:[0-9a-f]{64}$' AND
         command_semantic_sha256 ~ '^[0-9a-f]{64}$')
    ) NOT VALID;

ALTER TABLE code_signing_operations
    VALIDATE CONSTRAINT code_signing_approved_source_complete;
