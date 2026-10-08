-- PAM revocation is an asynchronous target operation. Keep the initiating
-- operator and reason separate from the original access justification.
ALTER TABLE pam_sessions
    ADD COLUMN revocation_requested_by text NOT NULL DEFAULT '',
    ADD COLUMN revocation_reason text NOT NULL DEFAULT '',
    ADD COLUMN revocation_requested_at timestamptz;

CREATE INDEX pam_sessions_revoking_idx
    ON pam_sessions (tenant_id, revocation_requested_at, id)
    WHERE status = 'revoking';
