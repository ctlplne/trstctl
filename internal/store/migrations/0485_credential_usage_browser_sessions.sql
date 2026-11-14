-- M1-L2: a person's browser sign-in is recorded as a use of kind
-- browser_session (its credential id is the tenant-bound subject reference,
-- never the subject). The usage and source tables' kind checks admit it; the
-- hourly windows stay API-token only. Existing rows hold api_token or
-- machine_auth, which the checks still admit.

ALTER TABLE credential_usage
    DROP CONSTRAINT IF EXISTS credential_usage_kind_check;

ALTER TABLE credential_usage
    ADD CONSTRAINT credential_usage_kind_check
        CHECK (kind IN ('api_token', 'machine_auth', 'browser_session')) NOT VALID;

ALTER TABLE credential_usage
    VALIDATE CONSTRAINT credential_usage_kind_check;

ALTER TABLE credential_usage_sources
    DROP CONSTRAINT IF EXISTS credential_usage_sources_kind_check;

ALTER TABLE credential_usage_sources
    ADD CONSTRAINT credential_usage_sources_kind_check
        CHECK (kind IN ('api_token', 'machine_auth', 'browser_session')) NOT VALID;

ALTER TABLE credential_usage_sources
    VALIDATE CONSTRAINT credential_usage_sources_kind_check;
