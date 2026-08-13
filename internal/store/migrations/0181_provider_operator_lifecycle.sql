-- migrate: no-transaction
-- AUD-58: Provider operator lifecycle and complete delegation evidence.
--
-- Provider operators are control-plane principals, not customer-tenant users.
-- Their rows still carry tenant_id and FORCE RLS (AN-1); the fixed zero UUID is
-- a non-customer authority partition reached only through the system pool. The
-- provider HTTP plane never accepts this value from a request.

CREATE TABLE IF NOT EXISTS provider_operators (
    tenant_id        uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    id               text        NOT NULL,
    external_id      text        NOT NULL,
    user_name        text        NOT NULL,
    email            text        NOT NULL DEFAULT '',
    display_name     text        NOT NULL DEFAULT '',
    role             text        NOT NULL CHECK (role IN ('admin', 'operator')),
    active           boolean     NOT NULL,
    source           text        NOT NULL,
    created_at       timestamptz NOT NULL,
    updated_at       timestamptz NOT NULL,
    deprovisioned_at timestamptz,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, external_id),
    UNIQUE (tenant_id, user_name)
);

ALTER TABLE provider_operators ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_operators FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS provider_operators_isolation ON provider_operators;
CREATE POLICY provider_operators_isolation ON provider_operators
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX IF NOT EXISTS provider_operators_active_idx
    ON provider_operators (tenant_id, active, user_name);

GRANT SELECT, INSERT, UPDATE, DELETE ON provider_operators TO trstctl_app;

-- A delegation used to disappear on revoke, which erased the answer to "who
-- used to have access?". Keep the row and its exact lifecycle instead.
ALTER TABLE provider_operator_delegations
    ADD COLUMN IF NOT EXISTS tenant_id     uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    ADD COLUMN IF NOT EXISTS source       text        NOT NULL DEFAULT 'legacy_local_command',
    ADD COLUMN IF NOT EXISTS expires_at   timestamptz,
    ADD COLUMN IF NOT EXISTS last_used_at timestamptz,
    ADD COLUMN IF NOT EXISTS revoked_at   timestamptz,
    ADD COLUMN IF NOT EXISTS revoked_by   text        NOT NULL DEFAULT '';

-- The legacy primary key already uniquely identifies the only supported fixed
-- Provider authority partition. Rewriting it only to prepend a constant
-- tenant_id would take ACCESS EXCLUSIVE on a live authority table without
-- increasing isolation, so 0181 deliberately preserves it.

ALTER TABLE provider_operator_delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_operator_delegations FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS provider_operator_delegations_isolation ON provider_operator_delegations;
CREATE POLICY provider_operator_delegations_isolation ON provider_operator_delegations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- online-safe: CONCURRENTLY keeps legacy Provider grant/revoke writes available
-- while PostgreSQL scans the populated delegation table; the populated AUD-58
-- migration harness proves every old row and its fixed authority partition.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS provider_operator_delegations_tenant_identity_idx
    ON provider_operator_delegations (tenant_id, operator_id, customer_tenant_id, operation);

CREATE INDEX CONCURRENTLY IF NOT EXISTS provider_operator_delegations_active_idx
    ON provider_operator_delegations (tenant_id, operator_id, customer_tenant_id, operation)
    WHERE revoked_at IS NULL;

COMMENT ON TABLE provider_operators IS
    'Event-projected Provider operator directory. The fixed zero-UUID RLS partition is provider-global authority, never a customer tenant.';

COMMENT ON TABLE provider_operator_delegations IS
    'Event-projected Provider customer authority. tenant_id is the fixed zero-UUID Provider authority partition; customer_tenant_id names the separately delegated customer.';
