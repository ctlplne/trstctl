-- 0020_outbox_retention.sql — bound the outbox table (SPINE-003).
--
-- outbox (AN-6) records one row per external effect (upstream CA, connector,
-- webhook, notification). On success the dispatcher sets status='delivered' and
-- stamps delivered_at (orchestrator/outbox.go), but nothing ever removed a
-- delivered row: every external effect accumulated forever, so the table, its
-- indexes, and every backup grew without bound and eventually needed a manual
-- cleanup/VACUUM. A background sweep now deletes delivered rows whose delivered_at
-- is older than a short retention window. Pending/failed rows (status <> 'delivered')
-- are never touched, so at-least-once delivery and the observability of stuck/failed
-- entries are preserved.
--
-- This partial index makes the sweep's predicate (DELETE … WHERE status='delivered'
-- AND delivered_at < cutoff) and the bound check cheap: it covers only delivered
-- rows and lets the delete scan just the eligible tail rather than the whole table.
-- The hot claim path keeps using outbox_due_idx (status='pending'); a delivered row
-- never matches that index. RLS and grants are inherited from 0003 (outbox); the
-- sweep is a cross-tenant system operation on the pool (RLS-bypassing), like the
-- dispatcher and the idempotency-key GC.
--
-- The grant must also allow DELETE on outbox: migration 0003 granted only
-- SELECT/INSERT/UPDATE, so the retention sweep needs DELETE added here.

CREATE INDEX IF NOT EXISTS outbox_delivered_at_idx
    ON outbox (delivered_at)
    WHERE status = 'delivered';

GRANT DELETE ON outbox TO trstctl_app;
