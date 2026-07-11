-- 0082_connector_right_size_operations.sql -- durable connector.right_size state.
-- migrate: no-transaction
--
-- A right-size remediation run is also the tenant-scoped operation record. The
-- immutable request binding and initial HTTP response outlive generic
-- idempotency-key retention, while terminal worker events advance status/phase
-- without changing the replay response. RLS already protects this table; these
-- columns deliberately contain no entitlement token or credential material.

ALTER TABLE remediation_playbook_runs
    ADD COLUMN IF NOT EXISTS request_binding text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS initial_http_status integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS initial_response bytea NOT NULL DEFAULT ''::bytea,
    ADD COLUMN IF NOT EXISTS terminal_reason text NOT NULL DEFAULT '';

-- online-safe: the metadata-only defaults avoid a table rewrite, while the
-- concurrent partial index does not block remediation evidence writes. Every
-- statement is idempotent because the migration ledger is recorded separately.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS remediation_playbook_runs_right_size_idempotency_idx
    ON remediation_playbook_runs (tenant_id, idempotency_key)
    WHERE action = 'right_size' AND request_binding <> '' AND idempotency_key <> '';

COMMENT ON COLUMN remediation_playbook_runs.request_binding IS
    'SHA-256 binding of authenticated principal, HTTP method, exact escaped path, and canonical right-size command';
COMMENT ON COLUMN remediation_playbook_runs.initial_response IS
    'Exact credential-free HTTP response bytes returned for durable right-size idempotency replay';
