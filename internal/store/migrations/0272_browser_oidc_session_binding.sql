-- SPDX-License-Identifier: BUSL-1.1
-- Backchannel logout is authorized by a verified OIDC issuer/client pair.
-- Existing unbound cookies are legacy and fail closed after this migration;
-- operators reauthenticate once so an IdP logout cannot miss an old cookie.
ALTER TABLE browser_sessions
    ADD COLUMN IF NOT EXISTS auth_method text NOT NULL DEFAULT 'legacy',
    ADD COLUMN IF NOT EXISTS oidc_provider_hash char(64),
    ADD COLUMN IF NOT EXISTS oidc_sid_hash char(64),
    ADD COLUMN IF NOT EXISTS oidc_id_token_iat bigint;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'browser_sessions_auth_method_chk') THEN
        ALTER TABLE browser_sessions ADD CONSTRAINT browser_sessions_auth_method_chk
            CHECK (auth_method IN ('legacy', 'other', 'oidc')) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'browser_sessions_oidc_binding_chk') THEN
        ALTER TABLE browser_sessions ADD CONSTRAINT browser_sessions_oidc_binding_chk
            CHECK ((auth_method = 'oidc' AND oidc_provider_hash IS NOT NULL
                AND oidc_provider_hash ~ '^[0-9a-f]{64}$' AND oidc_id_token_iat IS NOT NULL)
                OR (auth_method <> 'oidc' AND oidc_provider_hash IS NULL AND oidc_sid_hash IS NULL AND oidc_id_token_iat IS NULL)) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'browser_sessions_oidc_sid_chk') THEN
        ALTER TABLE browser_sessions ADD CONSTRAINT browser_sessions_oidc_sid_chk
            CHECK (oidc_sid_hash IS NULL OR oidc_sid_hash ~ '^[0-9a-f]{64}$') NOT VALID;
    END IF;
END $$;

ALTER TABLE browser_sessions VALIDATE CONSTRAINT browser_sessions_auth_method_chk;
ALTER TABLE browser_sessions VALIDATE CONSTRAINT browser_sessions_oidc_binding_chk;
ALTER TABLE browser_sessions VALIDATE CONSTRAINT browser_sessions_oidc_sid_chk;

