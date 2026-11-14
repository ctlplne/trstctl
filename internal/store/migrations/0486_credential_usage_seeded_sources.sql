-- M1-L4: when usage began, a person's latest browser sign-in that the session
-- store still held is seeded once as a use whose source kind is seeded (source
-- session_store): read from what trstctl held rather than observed from a
-- network. The source table's check admits it; existing rows hold network or
-- attestation, which it still admits.

ALTER TABLE credential_usage_sources
    DROP CONSTRAINT IF EXISTS credential_usage_sources_source_kind_check;

ALTER TABLE credential_usage_sources
    ADD CONSTRAINT credential_usage_sources_source_kind_check
        CHECK (source_kind IN ('network', 'attestation', 'seeded')) NOT VALID;

ALTER TABLE credential_usage_sources
    VALIDATE CONSTRAINT credential_usage_sources_source_kind_check;
