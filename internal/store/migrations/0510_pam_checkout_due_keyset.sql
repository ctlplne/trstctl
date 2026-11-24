-- CR-086: the expiry worker advances a bounded cross-tenant scan past rows it
-- could not end. Keep the keyset order indexed for large overdue populations.
-- migrate: no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS pam_checkouts_due_keyset_idx
    ON pam_checkouts (expires_at, tenant_id, request_id)
    WHERE status = 'revealed';

-- The fair first page seeks at most 25 due rows per registered tenant.
CREATE INDEX CONCURRENTLY IF NOT EXISTS pam_checkouts_due_by_tenant_idx
    ON pam_checkouts (tenant_id, expires_at, request_id)
    WHERE status = 'revealed';
