-- The immutable lifecycle event already carries these public fields. Preserve
-- them in its existing tenant/RLS projection for exact asynchronous result reads.
-- Existing rows remain unavailable until an authorized projection rebuild; never
-- guess a request key or CSR from an identity name, owner, or current authority.
ALTER TABLE identity_transitions
    ADD COLUMN IF NOT EXISTS idempotency_key text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS subject_csr_pem text NOT NULL DEFAULT '';

-- Both fields are projections of retained certificate events, not mutable
-- discovery metadata. Zero is a recovery cursor, never an invented issuance.
ALTER TABLE certificates
    ADD COLUMN IF NOT EXISTS recording_event_id text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS recording_sequence bigint NOT NULL DEFAULT 0 CHECK (recording_sequence >= 0),
    ADD COLUMN IF NOT EXISTS issuance_event_id text NOT NULL DEFAULT '';
