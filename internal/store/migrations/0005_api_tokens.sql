-- API tokens (F13): scoped bearer tokens for CI/CD. Only the SHA-256 hash of the
-- token secret is stored, never the secret itself. Per AN-1 the table carries
-- tenant_id and is confined by row-level security; token creation runs under the
-- tenant's RLS context, while authentication looks a token up by its (globally
-- unique, high-entropy) hash as a system operation before any tenant is known.
CREATE TABLE api_tokens (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    token_hash text NOT NULL UNIQUE,
    subject    text NOT NULL,
    scopes     text[] NOT NULL DEFAULT '{}',
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE api_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_tokens FORCE ROW LEVEL SECURITY;

CREATE POLICY api_tokens_isolation ON api_tokens
    USING (tenant_id = current_setting('certctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('certctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON api_tokens TO certctl_app;
