-- SPDX-License-Identifier: BUSL-1.1

-- Browser authentication must survive a process restart and must work when a
-- load balancer sends consecutive requests to different control-plane replicas.
-- Store only one-way digests of the random session ID and authenticated subject;
-- the signed HttpOnly cookie carries the user's non-secret display claims.
CREATE TABLE browser_sessions (
    tenant_id       uuid        NOT NULL,
    session_hash    text        NOT NULL,
    subject_hash    text        NOT NULL,
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL,
    last_seen_at    timestamptz NOT NULL,
    revoked_at      timestamptz,
    PRIMARY KEY (tenant_id, session_hash),
    CONSTRAINT browser_sessions_session_hash_chk CHECK (session_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT browser_sessions_subject_hash_chk CHECK (subject_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT browser_sessions_expiry_chk CHECK (expires_at > created_at)
);

ALTER TABLE browser_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE browser_sessions FORCE ROW LEVEL SECURITY;

CREATE POLICY browser_sessions_isolation ON browser_sessions
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX browser_sessions_subject_idx
    ON browser_sessions (tenant_id, subject_hash, expires_at);

CREATE INDEX browser_sessions_expiry_idx
    ON browser_sessions (tenant_id, expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON browser_sessions TO trstctl_app;

COMMENT ON TABLE browser_sessions IS
    'Tenant-isolated, pseudonymous browser-session revocation and idle-time authority shared by all control-plane replicas.';
