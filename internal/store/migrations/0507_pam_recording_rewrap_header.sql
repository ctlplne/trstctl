-- A signed PAM recording manifest commits to the original immutable object.
-- Key-domain changes store only the new authenticated envelope header here;
-- playback combines it with the original, digest-checked payload ciphertext.
ALTER TABLE pam_session_recording_chunks
    ADD COLUMN rewrap_header bytea NOT NULL DEFAULT ''::bytea,
    ADD COLUMN rewrap_event_sequence bigint NOT NULL DEFAULT 0,
    ADD CONSTRAINT pam_recording_rewrap_header_bound CHECK (octet_length(rewrap_header) <= 131326);
