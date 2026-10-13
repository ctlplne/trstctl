-- A revoked bearer must stop authenticating as soon as its first command is
-- durable, even when broker publication or SQL projection has not completed.
-- This operational command fence is independent PostgreSQL backup state. The
-- projector strips actor/reason bytes at completion but retains an opaque
-- terminal denial marker so a partial read-model replay cannot reopen a token.
CREATE TABLE api_token_revocation_commands (
    tenant_id uuid NOT NULL,
    token_id uuid NOT NULL,
    event_id uuid NOT NULL,
    event_time timestamptz NOT NULL,
    event_actor jsonb,
    event_payload bytea,
    payload_sha256 char(64),
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, token_id),
    UNIQUE (tenant_id, event_id),
    CHECK ((status = 'pending' AND event_payload IS NOT NULL AND
            payload_sha256 ~ '^[0-9a-f]{64}$') OR
           (status = 'completed' AND event_payload IS NULL AND
            payload_sha256 IS NULL AND event_actor IS NULL))
);

ALTER TABLE api_token_revocation_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_token_revocation_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY api_token_revocation_commands_isolation
    ON api_token_revocation_commands
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON api_token_revocation_commands TO trstctl_app;
