-- Honeytokens are deliberately recognizable API bearer values, but never
-- api_tokens: an accidental role grant must not turn bait into authority.
CREATE TABLE honey_tokens (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    placement text NOT NULL,
    token_hash text NOT NULL UNIQUE,
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'triggered', 'revoked')),
    created_at timestamptz NOT NULL,
    triggered_at timestamptz,
    trigger_method text,
    trigger_path text,
    revoked_at timestamptz,
    CHECK (length(name) BETWEEN 1 AND 128),
    CHECK (length(placement) BETWEEN 1 AND 256)
);
CREATE INDEX honey_tokens_tenant_created_idx ON honey_tokens (tenant_id, created_at DESC, id);
ALTER TABLE honey_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE honey_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY honey_tokens_isolation ON honey_tokens
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON honey_tokens TO trstctl_app;
