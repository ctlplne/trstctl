-- 0073_secret_integration_jobs.sql -- restart-safe dynamic-secret leases and
-- secret-sync delivery evidence.
--
-- Both tables are tenant-scoped read models projected from immutable lifecycle
-- events. The external work itself remains in the existing outbox (AN-6). These
-- rows deliberately contain no plaintext generated credential bytes and no
-- synchronized secret values. dynamic_secret_leases keeps the provider's
-- revocation handle plus an envelope-sealed credential result so an API retry
-- after provider success returns the identical credential without another
-- external call. secret_sync_jobs keeps only source/version metadata plus a
-- digest.

CREATE TABLE IF NOT EXISTS dynamic_secret_leases (
    tenant_id          uuid        NOT NULL,
    id                 text        NOT NULL,
    idempotency_key    text        NOT NULL,
    provider           text        NOT NULL,
    role               text        NOT NULL,
    backend_ref        text        NOT NULL,
    sealed_credential  bytea       NOT NULL DEFAULT ''::bytea,
    state              text        NOT NULL,
    issue_outbox_id    bigint      NOT NULL,
    revocation_status  text        NOT NULL DEFAULT 'none',
    revoke_outbox_id   bigint,
    last_error         text        NOT NULL DEFAULT '',
    issued_at          timestamptz NOT NULL,
    expires_at         timestamptz NOT NULL,
    hard_expires_at    timestamptz NOT NULL,
    revoked_at         timestamptz,
    updated_at         timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT dynamic_secret_leases_required_chk
        CHECK (id <> '' AND idempotency_key <> '' AND provider <> '' AND role <> '' AND issue_outbox_id > 0),
    CONSTRAINT dynamic_secret_leases_state_chk
        CHECK (state IN ('pending', 'active', 'failed', 'revoked')),
    CONSTRAINT dynamic_secret_leases_revocation_status_chk
        CHECK (revocation_status IN ('none', 'pending', 'completed', 'failed')),
    CONSTRAINT dynamic_secret_leases_expiry_chk
        CHECK (issued_at <= expires_at AND expires_at <= hard_expires_at),
    CONSTRAINT dynamic_secret_leases_revocation_shape_chk
        CHECK (
            (state = 'pending'
                AND revocation_status = 'none'
                AND revoke_outbox_id IS NULL
                AND revoked_at IS NULL
                AND backend_ref = ''
                AND octet_length(sealed_credential) = 0
                AND last_error = '')
            OR
            (state = 'active'
                AND revocation_status = 'none'
                AND revoke_outbox_id IS NULL
                AND revoked_at IS NULL
                AND backend_ref <> ''
                AND octet_length(sealed_credential) > 0
                AND last_error = '')
            OR
            (state = 'failed'
                AND revocation_status = 'none'
                AND revoke_outbox_id IS NULL
                AND revoked_at IS NULL
                AND octet_length(sealed_credential) = 0
                AND last_error <> '')
            OR
            (state = 'revoked'
                AND revocation_status <> 'none'
                AND revoke_outbox_id IS NOT NULL
                AND revoked_at IS NOT NULL
                AND backend_ref <> ''
                AND octet_length(sealed_credential) = 0)
        )
);

ALTER TABLE dynamic_secret_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE dynamic_secret_leases FORCE ROW LEVEL SECURITY;

CREATE POLICY dynamic_secret_leases_isolation ON dynamic_secret_leases
    USING (tenant_id::text = current_setting('trstctl.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('trstctl.tenant_id', true));

CREATE UNIQUE INDEX IF NOT EXISTS dynamic_secret_leases_revoke_outbox_idx
    ON dynamic_secret_leases (tenant_id, revoke_outbox_id)
    WHERE revoke_outbox_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS dynamic_secret_leases_issue_outbox_idx
    ON dynamic_secret_leases (tenant_id, issue_outbox_id);

CREATE UNIQUE INDEX IF NOT EXISTS dynamic_secret_leases_idempotency_idx
    ON dynamic_secret_leases (tenant_id, idempotency_key);

CREATE INDEX IF NOT EXISTS dynamic_secret_leases_due_idx
    ON dynamic_secret_leases (tenant_id, expires_at, id)
    WHERE state = 'active';

CREATE INDEX IF NOT EXISTS dynamic_secret_leases_provider_state_idx
    ON dynamic_secret_leases (tenant_id, provider, state, id);

GRANT SELECT, INSERT, UPDATE, DELETE ON dynamic_secret_leases TO trstctl_app;

CREATE TABLE IF NOT EXISTS secret_sync_jobs (
    tenant_id       uuid        NOT NULL,
    id              text        NOT NULL,
    secret_name     text        NOT NULL,
    secret_version  bigint      NOT NULL,
    target           text        NOT NULL,
    remote_key       text        NOT NULL,
    value_digest     text        NOT NULL,
    status           text        NOT NULL,
    outbox_id        bigint      NOT NULL,
    attempts         integer     NOT NULL DEFAULT 0,
    remote_version   text        NOT NULL DEFAULT '',
    last_error       text        NOT NULL DEFAULT '',
    idempotency_key  text        NOT NULL,
    requested_at     timestamptz NOT NULL,
    updated_at       timestamptz NOT NULL,
    delivered_at     timestamptz,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT secret_sync_jobs_required_chk
        CHECK (
            id <> ''
            AND secret_name <> ''
            AND secret_version > 0
            AND target <> ''
            AND remote_key <> ''
            AND value_digest <> ''
            AND idempotency_key <> ''
        ),
    CONSTRAINT secret_sync_jobs_status_chk
        CHECK (status IN ('pending', 'delivered', 'failed')),
    CONSTRAINT secret_sync_jobs_attempts_chk
        CHECK (attempts >= 0),
    CONSTRAINT secret_sync_jobs_delivery_shape_chk
        CHECK (
            (status = 'delivered' AND delivered_at IS NOT NULL)
            OR
            (status <> 'delivered' AND delivered_at IS NULL)
        )
);

ALTER TABLE secret_sync_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_sync_jobs FORCE ROW LEVEL SECURITY;

CREATE POLICY secret_sync_jobs_isolation ON secret_sync_jobs
    USING (tenant_id::text = current_setting('trstctl.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('trstctl.tenant_id', true));

CREATE UNIQUE INDEX IF NOT EXISTS secret_sync_jobs_outbox_idx
    ON secret_sync_jobs (tenant_id, outbox_id);

CREATE UNIQUE INDEX IF NOT EXISTS secret_sync_jobs_idempotency_idx
    ON secret_sync_jobs (tenant_id, idempotency_key);

CREATE INDEX IF NOT EXISTS secret_sync_jobs_status_idx
    ON secret_sync_jobs (tenant_id, target, status, id);

CREATE INDEX IF NOT EXISTS secret_sync_jobs_latest_idx
    ON secret_sync_jobs
       (tenant_id, secret_name, target, remote_key, requested_at DESC, id DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON secret_sync_jobs TO trstctl_app;
