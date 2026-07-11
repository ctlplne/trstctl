-- SPDX-License-Identifier: MPL-2.0
-- Durable authenticated command identities for dynamic-secret lifecycle
-- mutations and secret-sync delivery.
--
-- The short-lived HTTP idempotency response cache is not the authority for an
-- external credential whose lifetime is longer than that cache.  This projected
-- table keeps the raw idempotency-key claim, authenticated request digest, exact
-- command, and non-secret public response for the life of the event log (AN-2).

CREATE TABLE IF NOT EXISTS dynamic_secret_operations (
    tenant_id        uuid        NOT NULL,
    operation_id     text        NOT NULL,
    idempotency_key  text        NOT NULL,
    request_binding  text        NOT NULL,
    action            text        NOT NULL,
    lease_id          text        NOT NULL,
    response          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    status            text        NOT NULL,
    last_error        text        NOT NULL DEFAULT '',
    created_at        timestamptz NOT NULL,
    updated_at        timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT dynamic_secret_operations_required_chk
        CHECK (
            operation_id <> ''
            AND idempotency_key <> ''
            AND request_binding <> ''
            AND lease_id <> ''
            AND jsonb_typeof(response) = 'object'
        ),
    CONSTRAINT dynamic_secret_operations_action_chk
        CHECK (action IN ('issue', 'renew', 'revoke')),
    CONSTRAINT dynamic_secret_operations_status_chk
        CHECK (status IN ('pending', 'completed', 'failed')),
    CONSTRAINT dynamic_secret_operations_failure_shape_chk
        CHECK ((status = 'failed' AND last_error <> '') OR (status <> 'failed' AND last_error = ''))
);

ALTER TABLE dynamic_secret_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE dynamic_secret_operations FORCE ROW LEVEL SECURITY;

CREATE POLICY dynamic_secret_operations_isolation ON dynamic_secret_operations
    USING (tenant_id::text = current_setting('trstctl.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('trstctl.tenant_id', true));

CREATE UNIQUE INDEX IF NOT EXISTS dynamic_secret_operations_idempotency_idx
    ON dynamic_secret_operations (tenant_id, idempotency_key);

CREATE INDEX IF NOT EXISTS dynamic_secret_operations_lease_idx
    ON dynamic_secret_operations (tenant_id, lease_id, created_at, operation_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON dynamic_secret_operations TO trstctl_app;

-- Existing issue rows predate the command table.  Bind them fail-closed: rows
-- with an authenticated digest preserve it; truly old rows get a sentinel that
-- no authenticated API request can reproduce.
INSERT INTO dynamic_secret_operations
       (tenant_id, operation_id, idempotency_key, request_binding, action,
        lease_id, response, status, last_error, created_at, updated_at)
SELECT tenant_id,
       'issue:' || id,
       idempotency_key,
       CASE WHEN request_binding = '' THEN 'legacy-unbound' ELSE request_binding END,
       'issue',
       id,
       '{}'::jsonb,
       CASE state WHEN 'pending' THEN 'pending' WHEN 'failed' THEN 'failed' ELSE 'completed' END,
       CASE state WHEN 'failed' THEN last_error ELSE '' END,
       issued_at,
       updated_at
  FROM dynamic_secret_leases
ON CONFLICT (tenant_id, idempotency_key) DO NOTHING;

ALTER TABLE secret_sync_jobs
    ADD COLUMN IF NOT EXISTS request_binding text NOT NULL DEFAULT '';
