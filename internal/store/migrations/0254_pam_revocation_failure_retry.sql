-- Preserve the exact event-derived provider-removal attempt and terminal result.
ALTER TABLE pam_sessions
    ADD COLUMN revocation_idempotency_key text NOT NULL DEFAULT '',
    ADD COLUMN revocation_failure text NOT NULL DEFAULT '',
    ADD COLUMN revocation_failed_at timestamptz;
