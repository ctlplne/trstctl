-- A255: recordings of sessions through the access gateway. The gateway masks
-- secrets before anything leaves it and uploads each held session's recording
-- in ordered chunks; the control plane seals every chunk for the tenant into
-- the object store and chains its digest, and seals the recording with a
-- signed manifest when the session ends. These rows index what the object
-- store holds; they are projected from pam.session.recording_* events.
CREATE TABLE IF NOT EXISTS pam_session_recordings (
    tenant_id uuid NOT NULL,
    session_id uuid NOT NULL,
    gateway_agent_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('recording', 'sealed', 'deleted')),
    chunks integer NOT NULL DEFAULT 0,
    bytes bigint NOT NULL DEFAULT 0,
    chain_head text NOT NULL DEFAULT '',
    started_at timestamptz NOT NULL,
    last_chunk_at timestamptz NOT NULL,
    sealed_at timestamptz,
    final_received boolean NOT NULL DEFAULT false,
    manifest_ref text NOT NULL DEFAULT '',
    manifest_sha256 text NOT NULL DEFAULT '',
    manifest_signature text NOT NULL DEFAULT '',
    -- A legal hold keeps a recording past its retention; deleted_at marks a
    -- recording whose objects retention removed (its index stays).
    legal_hold boolean NOT NULL DEFAULT false,
    legal_hold_reason text NOT NULL DEFAULT '',
    deleted_at timestamptz,
    PRIMARY KEY (tenant_id, session_id)
);

ALTER TABLE pam_session_recordings ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_session_recordings FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_session_recordings_isolation ON pam_session_recordings
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_session_recordings TO trstctl_app;

CREATE INDEX IF NOT EXISTS pam_session_recordings_open_idx
    ON pam_session_recordings (status, last_chunk_at) WHERE status = 'recording';

-- One row per stored chunk, in storage order (ord). attempt and seq are the
-- gateway's: a re-claimed session's gateway starts a new attempt at seq 0.
-- chain = SHA-256(previous chain || plaintext SHA-256), from 64 zeros.
CREATE TABLE IF NOT EXISTS pam_session_recording_chunks (
    tenant_id uuid NOT NULL,
    session_id uuid NOT NULL,
    ord integer NOT NULL CHECK (ord >= 0),
    attempt integer NOT NULL CHECK (attempt > 0),
    seq integer NOT NULL CHECK (seq >= 0),
    object_ref text NOT NULL,
    sha256 text NOT NULL,
    sealed_sha256 text NOT NULL,
    chain text NOT NULL,
    size integer NOT NULL CHECK (size >= 0),
    stored_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, session_id, ord),
    UNIQUE (tenant_id, session_id, attempt, seq)
);

ALTER TABLE pam_session_recording_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_session_recording_chunks FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_session_recording_chunks_isolation ON pam_session_recording_chunks
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_session_recording_chunks TO trstctl_app;
