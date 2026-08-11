-- migrate: no-transaction
-- Privacy-erasure lookup for unbound application-secret mutation fences.
--
-- online-safe: CONCURRENTLY avoids blocking writes on the live command-fence
-- table. A failed/interrupted concurrent build leaves a same-name INVALID index;
-- IF NOT EXISTS would silently accept that unusable catalog row and let the
-- migration ledger lie. Always drop the unledgered attempt, whether invalid or
-- fully built before a process exit, then rebuild it and ledger only success.

DROP INDEX CONCURRENTLY IF EXISTS application_secret_mutation_fences_requester_ref_idx;

CREATE INDEX CONCURRENTLY application_secret_mutation_fences_requester_ref_idx
    ON application_secret_mutation_fences (tenant_id, requester_ref)
    WHERE requester_ref IS NOT NULL;
