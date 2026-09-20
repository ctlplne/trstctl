-- SPDX-License-Identifier: BUSL-1.1
-- Durable, event-projected code-signing commands.  The command body is sealed
-- with the deployment KEK before it reaches PostgreSQL; only its request hash
-- and public routing metadata are readable here.

CREATE TABLE code_signing_operations (
    tenant_id UUID NOT NULL,
    operation_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('key', 'keyless')),
    request_hash TEXT NOT NULL,
    sealed_command BYTEA NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'completed', 'failed')),
    response BYTEA NOT NULL DEFAULT ''::bytea,
    ephemeral_handle TEXT NOT NULL DEFAULT '',
    cleanup_status TEXT NOT NULL DEFAULT 'not_required'
        CHECK (cleanup_status IN ('not_required', 'pending', 'completed')),
    -- Historical delivery evidence only. The outbox retention worker must be
    -- free to reclaim delivered command/cleanup rows after their audit window.
    command_outbox_id BIGINT NOT NULL,
    cleanup_outbox_id BIGINT,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    UNIQUE (tenant_id, idempotency_key),
    CHECK (operation_id <> '' AND idempotency_key <> '' AND request_hash <> ''),
    CHECK (octet_length(sealed_command) > 0),
    CHECK ((status = 'completed' AND octet_length(response) > 0) OR status <> 'completed')
);

CREATE INDEX code_signing_operations_tenant_status_idx
    ON code_signing_operations (tenant_id, status, updated_at DESC);

ALTER TABLE code_signing_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE code_signing_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY code_signing_operations_isolation ON code_signing_operations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON code_signing_operations TO trstctl_app;
