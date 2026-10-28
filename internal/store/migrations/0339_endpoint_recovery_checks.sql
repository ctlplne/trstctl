-- A210: the latest recovery check of a contained host target. A person queues
-- it; the target's enrolled host agent answers in a signed job receipt whether
-- its operator-owned profile pins an action that brings the listener back
-- (digests only, never a path) and what the listener serves now. A projection of
-- the endpoint.recovery_check.* events; a newer request replaces the row.
CREATE TABLE IF NOT EXISTS endpoint_recovery_checks (
    tenant_id           uuid        NOT NULL,
    target_id           uuid        NOT NULL,
    check_id            uuid        NOT NULL,
    target_revision     text        NOT NULL,
    agent_id            uuid        NOT NULL,
    requested_by        text        NOT NULL DEFAULT '',
    requested_at        timestamptz NOT NULL,
    request_sequence    bigint      NOT NULL CHECK (request_sequence > 0),
    status              text        NOT NULL CHECK (status IN ('queued', 'checked', 'failed')),
    recovery            text        NOT NULL DEFAULT ''
                                    CHECK (recovery IN ('', 'pinned', 'no_recovery_action', 'no_binding')),
    recovery_action     text        NOT NULL DEFAULT '',
    executable_sha256   text        NOT NULL DEFAULT '',
    argv_sha256         text        NOT NULL DEFAULT '',
    listener            text        NOT NULL DEFAULT ''
                                    CHECK (listener IN ('', 'none', 'stopped', 'serving', 'serving_revoked', 'unverified')),
    serving_fingerprint text        NOT NULL DEFAULT '',
    failure             text        NOT NULL DEFAULT '',
    job_id              bigint,
    evidence_digest     text        NOT NULL DEFAULT '',
    checked_at          timestamptz,
    event_sequence      bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, target_id)
);
ALTER TABLE endpoint_recovery_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpoint_recovery_checks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS endpoint_recovery_checks_isolation ON endpoint_recovery_checks;
CREATE POLICY endpoint_recovery_checks_isolation ON endpoint_recovery_checks
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON endpoint_recovery_checks TO trstctl_app;
