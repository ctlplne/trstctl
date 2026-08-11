-- AUD-77: a durable, non-secret receipt for each authoritative served
-- application-secret mutation. The sealed secret store is independent PostgreSQL
-- state, while approval requests are rebuilt from the event log. Keeping this
-- receipt beside the sealed mutation lets a full read-model rebuild re-consume the
-- exact approval event without rotating/deleting the already-materialized secret a
-- second time. semantic_sha256 is a domain-separated digest over the immutable
-- event envelope and every security-relevant payload field except the approval
-- requester's privacy-rewriteable spelling. It binds ciphertext, never plaintext.

CREATE TABLE application_secret_mutation_receipts (
    tenant_id     UUID        NOT NULL,
    event_id      UUID        NOT NULL,
    semantic_sha256 CHAR(64)  NOT NULL,
    request_binding CHAR(64)  NOT NULL,
    secret_name   TEXT        NOT NULL,
    action        TEXT        NOT NULL,
    result_version INTEGER    NOT NULL,
    result_created_at TIMESTAMPTZ NOT NULL,
    result_updated_at TIMESTAMPTZ NOT NULL,
    applied_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, event_id),
    CHECK (semantic_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (request_binding ~ '^[0-9a-f]{64}$'),
    CHECK (length(btrim(secret_name)) > 0),
    CHECK (action IN ('create', 'rotate', 'recover', 'delete')),
    CHECK ((action = 'delete' AND result_version = 0) OR
           (action IN ('create', 'rotate', 'recover') AND result_version > 0))
);

ALTER TABLE application_secret_mutation_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE application_secret_mutation_receipts FORCE ROW LEVEL SECURITY;

CREATE POLICY application_secret_mutation_receipts_isolation
    ON application_secret_mutation_receipts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON application_secret_mutation_receipts TO trstctl_app;

COMMENT ON TABLE application_secret_mutation_receipts IS
    'Independent non-secret exact-event receipts committed beside served sealed secret mutations; restored with PostgreSQL state so approval rebuild cannot apply a mutation twice.';

-- A broker publish and its PostgreSQL projection cannot be one transaction. This
-- first-writer-wins fence is committed BEFORE approval creation or Append. A
-- competing command for the same secret therefore cannot append behind an
-- unprojected command. command_payload is ciphertext plus non-secret bindings;
-- approval stores the exact capability without its privacy-rewriteable requester.
CREATE TABLE application_secret_mutation_fences (
    tenant_id       UUID        NOT NULL,
    secret_name     TEXT        NOT NULL,
    operation       TEXT        NOT NULL,
    event_id        UUID        NOT NULL,
    event_type      TEXT        NOT NULL,
    schema_version  INTEGER     NOT NULL,
    approval_required BOOLEAN   NOT NULL,
    requester_sealed BYTEA,
    request_binding CHAR(64)    NOT NULL,
    command_payload BYTEA       NOT NULL,
    payload_sha256  CHAR(64)    NOT NULL,
    event_time      TIMESTAMPTZ,
    approval        JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, secret_name),
    UNIQUE (tenant_id, event_id),
    CHECK (length(btrim(secret_name)) > 0),
    CHECK (length(btrim(operation)) > 0),
    CHECK (length(btrim(event_type)) > 0),
    CHECK (schema_version > 0),
    CHECK (request_binding ~ '^[0-9a-f]{64}$'),
    CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (octet_length(command_payload) > 0),
    CHECK (NOT approval_required OR requester_sealed IS NOT NULL OR approval IS NOT NULL)
);

ALTER TABLE application_secret_mutation_fences ENABLE ROW LEVEL SECURITY;
ALTER TABLE application_secret_mutation_fences FORCE ROW LEVEL SECURITY;

CREATE POLICY application_secret_mutation_fences_isolation
    ON application_secret_mutation_fences
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON application_secret_mutation_fences TO trstctl_app;

COMMENT ON TABLE application_secret_mutation_fences IS
    'Durable per-secret first-command fence and canonical sealed command, retained across the NATS duplicate window and removed atomically with its mutation receipt.';
