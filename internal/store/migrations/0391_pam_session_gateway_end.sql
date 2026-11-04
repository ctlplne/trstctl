-- A255: a gateway session's own end, as its gateway reported it (deadline or
-- recalled). Until it arrives, a terminated session is uncertain up to its
-- native deadline; when it arrives, the termination is acknowledged.
ALTER TABLE pam_sessions
    ADD COLUMN IF NOT EXISTS gateway_ended_at timestamptz,
    ADD COLUMN IF NOT EXISTS gateway_ended text NOT NULL DEFAULT '';
