-- SPDX-License-Identifier: BUSL-1.1
-- migrate: no-transaction
-- Indexes build without blocking browser-session issue/revocation traffic.
CREATE INDEX CONCURRENTLY IF NOT EXISTS browser_sessions_oidc_subject_idx
    ON browser_sessions (tenant_id, oidc_provider_hash, subject_hash, oidc_sid_hash)
    WHERE auth_method = 'oidc' AND revoked_at IS NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS browser_sessions_oidc_sid_idx
    ON browser_sessions (tenant_id, oidc_provider_hash, oidc_sid_hash)
    WHERE auth_method = 'oidc' AND revoked_at IS NULL AND oidc_sid_hash IS NOT NULL;
