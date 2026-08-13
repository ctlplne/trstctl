-- migrate: no-transaction
-- SPDX-License-Identifier: MPL-2.0

-- AUD-70 active readers intentionally ignore retired CT watchlist history.
-- Both tables are already populated, so build the partial lookup indexes
-- concurrently and make retries harmless.
-- online-safe: CONCURRENTLY avoids blocking watchlist replacement and polling
-- while PostgreSQL builds the active-authority lookup.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ct_watched_domains_active_idx
    ON ct_watched_domains (tenant_id, domain)
    WHERE active;

-- online-safe: same live-table reasoning as the watched-domain index above.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ct_log_checkpoints_active_idx
    ON ct_log_checkpoints (tenant_id, log_url)
    WHERE active;
