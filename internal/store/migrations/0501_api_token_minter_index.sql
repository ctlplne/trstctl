-- SPDX-License-Identifier: BUSL-1.1
-- migrate: no-transaction
-- Offboarding finds a person's delegated tokens by the same opaque reference
-- used for member fences, without scanning another subject's token inventory.
CREATE INDEX CONCURRENTLY IF NOT EXISTS api_tokens_minted_by_ref_active_idx
    ON api_tokens (tenant_id, minted_by_ref, id)
    WHERE minted_by_ref <> '' AND revoked_at IS NULL;
