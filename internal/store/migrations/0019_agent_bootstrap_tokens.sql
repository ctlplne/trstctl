-- Agent bootstrap tokens (F3/F15, WIRE-003): durable, tenant-scoped, single-use
-- one-time tokens an agent presents once at /enroll/bootstrap. Previously these
-- lived in a process-local map[string]bool (lost on restart, not shared across
-- instances, and carrying no tenant) — the WIRE-003 defect. Persisting them here
-- makes a token (a) survive a control-plane restart, (b) be redeemable on any
-- instance, and (c) bound to the authorizing tenant so the issued agent
-- certificate can be stamped with that tenant (AN-1). Only the SHA-256 hash of the
-- token secret is stored, never the secret itself (the secret is shown once at
-- mint), exactly like api_tokens.
--
-- Single-use is enforced at redemption by an atomic conditional UPDATE that sets
-- used_at only when the row is still unused and unexpired (see RedeemBootstrapToken);
-- a token redeemed on one instance cannot be redeemed again anywhere.
--
-- Per AN-1 the table carries tenant_id and is confined by row-level security.
-- Minting runs under the authorizing tenant's RLS context; redemption looks the
-- token up by its globally-unique, high-entropy hash as a system operation (the
-- tenant is not known until the token resolves), exactly like api_tokens
-- authentication.
CREATE TABLE agent_bootstrap_tokens (
    id            uuid PRIMARY KEY,
    tenant_id     uuid        NOT NULL,
    token_hash    text        NOT NULL UNIQUE,
    -- allowed_identity optionally pins the agent common-name this token may enroll
    -- as (empty = any). It scopes a leaked token to one intended identity.
    allowed_identity text     NOT NULL DEFAULT '',
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE agent_bootstrap_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_bootstrap_tokens FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_bootstrap_tokens_isolation ON agent_bootstrap_tokens
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- Index the redemption lookup (by hash) and the expiry sweep.
CREATE INDEX agent_bootstrap_tokens_expires_idx ON agent_bootstrap_tokens (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_bootstrap_tokens TO trstctl_app;
