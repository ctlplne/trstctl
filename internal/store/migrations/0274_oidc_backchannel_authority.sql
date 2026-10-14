-- SPDX-License-Identifier: BUSL-1.1

-- A backchannel logout assertion does not carry trstctl's tenant ID. Keep the
-- pseudonymous routing index and exact-assertion receipt in a reserved auth
-- partition; every lookup still uses a fixed tenant_id predicate and FORCE RLS.
-- The customer session remains in its own tenant (and possibly silo) schema.
-- Reserve the internal UUID before these tables are served. A populated
-- customer registration with this UUID makes migration fail closed.
ALTER TABLE tenants ADD CONSTRAINT tenants_oidc_auth_partition_reserved_chk
    CHECK (tenant_id <> '00000000-0000-0000-0000-000000000002'::uuid) NOT VALID;
ALTER TABLE tenants VALIDATE CONSTRAINT tenants_oidc_auth_partition_reserved_chk;

-- A pre-0274 OIDC cookie has only a tenant-local subject digest. Its global
-- locator cannot be reconstructed without inventing the original verified
-- subject. Generation zero is therefore unbound and rejected by new readers.
-- A rolling old binary also continues to write zero and cannot create a cookie
-- that the new binary would silently accept without a locator. New writers
-- insert generation one and its locator in the same transaction.
ALTER TABLE browser_sessions
    ADD COLUMN oidc_locator_generation smallint NOT NULL DEFAULT 0;
ALTER TABLE browser_sessions
    ADD CONSTRAINT browser_sessions_oidc_locator_generation_chk
    CHECK (oidc_locator_generation IN (0, 1)
       AND (auth_method = 'oidc' OR oidc_locator_generation = 0)) NOT VALID;
ALTER TABLE browser_sessions VALIDATE CONSTRAINT browser_sessions_oidc_locator_generation_chk;

CREATE TABLE oidc_session_locators (
    tenant_id           uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000002',
    browser_tenant_id   uuid        NOT NULL,
    session_hash        char(64)    NOT NULL,
    provider_hash       char(64)    NOT NULL,
    global_subject_hash char(64)    NOT NULL,
    browser_subject_hash char(64)   NOT NULL,
    sid_hash            char(64),
    id_token_iat        bigint      NOT NULL,
    expires_at          timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, browser_tenant_id, session_hash),
    CONSTRAINT oidc_session_locators_partition_chk CHECK (tenant_id = '00000000-0000-0000-0000-000000000002'::uuid),
    CONSTRAINT oidc_session_locators_iat_chk CHECK (id_token_iat > 0),
    CONSTRAINT oidc_session_locators_hashes_chk CHECK (
        session_hash ~ '^[0-9a-f]{64}$' AND provider_hash ~ '^[0-9a-f]{64}$'
        AND global_subject_hash ~ '^[0-9a-f]{64}$' AND browser_subject_hash ~ '^[0-9a-f]{64}$'
        AND (sid_hash IS NULL OR sid_hash ~ '^[0-9a-f]{64}$'))
);
ALTER TABLE oidc_session_locators ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_session_locators FORCE ROW LEVEL SECURITY;
CREATE POLICY oidc_session_locators_isolation ON oidc_session_locators
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
CREATE INDEX oidc_session_locators_subject_idx
    ON oidc_session_locators (tenant_id, provider_hash, global_subject_hash, expires_at);
CREATE INDEX oidc_session_locators_sid_idx
    ON oidc_session_locators (tenant_id, provider_hash, sid_hash, expires_at)
    WHERE sid_hash IS NOT NULL;
CREATE INDEX oidc_session_locators_customer_idx
    ON oidc_session_locators (tenant_id, browser_tenant_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON oidc_session_locators TO trstctl_app;

-- The exact JTI receipt is also the login cutoff. A subject-only logout denies
-- ID tokens issued no later than the logout; a sid logout denies that IdP
-- session regardless of subject-only login time. Keep receipts through backup
-- so a crash, replica change or restore cannot reopen an old assertion.
CREATE TABLE oidc_logout_receipts (
    tenant_id           uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000002',
    provider_hash       char(64)    NOT NULL,
    jti_hash            char(64)    NOT NULL,
    assertion_hash      char(64)    NOT NULL,
    global_subject_hash char(64),
    sid_hash            char(64),
    logout_iat          bigint      NOT NULL,
    token_exp           bigint      NOT NULL,
    completed_at        timestamptz NOT NULL,
    revoked_sessions    integer     NOT NULL,
    PRIMARY KEY (tenant_id, provider_hash, jti_hash),
    CONSTRAINT oidc_logout_receipts_partition_chk CHECK (tenant_id = '00000000-0000-0000-0000-000000000002'::uuid),
    CONSTRAINT oidc_logout_receipts_scope_chk CHECK (global_subject_hash IS NOT NULL OR sid_hash IS NOT NULL),
    CONSTRAINT oidc_logout_receipts_counts_chk CHECK (logout_iat > 0 AND token_exp > logout_iat AND revoked_sessions >= 0),
    CONSTRAINT oidc_logout_receipts_hashes_chk CHECK (
        provider_hash ~ '^[0-9a-f]{64}$' AND jti_hash ~ '^[0-9a-f]{64}$'
        AND assertion_hash ~ '^[0-9a-f]{64}$'
        AND (global_subject_hash IS NULL OR global_subject_hash ~ '^[0-9a-f]{64}$')
        AND (sid_hash IS NULL OR sid_hash ~ '^[0-9a-f]{64}$'))
);
ALTER TABLE oidc_logout_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_logout_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY oidc_logout_receipts_isolation ON oidc_logout_receipts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
CREATE INDEX oidc_logout_receipts_subject_cutoff_idx
    ON oidc_logout_receipts (tenant_id, provider_hash, global_subject_hash, logout_iat DESC)
    WHERE global_subject_hash IS NOT NULL AND sid_hash IS NULL;
CREATE INDEX oidc_logout_receipts_sid_cutoff_idx
    ON oidc_logout_receipts (tenant_id, provider_hash, sid_hash)
    WHERE sid_hash IS NOT NULL;
GRANT SELECT, INSERT ON oidc_logout_receipts TO trstctl_app;
