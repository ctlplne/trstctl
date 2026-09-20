-- SPDX-License-Identifier: BUSL-1.1
-- Durable, event-projected managed-key lifecycle + external-action command state.

CREATE TABLE managed_key_operations (
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    operation_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('generate', 'rotate', 'revoke', 'zeroize')),
    key_id TEXT NOT NULL DEFAULT '',
    algorithm TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'completed', 'failed')),
    result_key_id TEXT NOT NULL DEFAULT '',
    public_der BYTEA NOT NULL DEFAULT ''::bytea,
    result_state TEXT NOT NULL DEFAULT '',
    -- Historical delivery evidence, not ownership. Delivered outbox rows are
    -- retention-GC'd; keeping the numeric id must not pin finished queue rows.
    outbox_id BIGINT NOT NULL,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, operation_id)
);

CREATE INDEX managed_key_operations_tenant_status_idx
    ON managed_key_operations (tenant_id, status, updated_at DESC);

CREATE TABLE managed_keys (
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    key_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    state TEXT NOT NULL CHECK (state IN ('active', 'superseded', 'revoked', 'zeroized')),
    public_der BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, provider, key_id)
);

CREATE INDEX managed_keys_tenant_state_idx
    ON managed_keys (tenant_id, state, updated_at DESC);

ALTER TABLE managed_key_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE managed_key_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY managed_key_operations_isolation ON managed_key_operations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

ALTER TABLE managed_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE managed_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY managed_keys_isolation ON managed_keys
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON managed_key_operations TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON managed_keys TO trstctl_app;
