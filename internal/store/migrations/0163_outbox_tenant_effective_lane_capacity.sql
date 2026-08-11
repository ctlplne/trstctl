-- migrate: no-transaction
-- 0163_outbox_tenant_effective_lane_capacity.sql -- AN-7 tenant receiver capacity.
--
-- A target id is tenant-local configuration. The processing cap therefore looks
-- up one tenant plus its effective receiver lane, while the separately bounded
-- destination-family worker pool continues to cap aggregate provider-plane work.
-- DROP makes an interrupted concurrent-build retry safe. Keep the older global
-- effect-lane index for mixed-version workers during a rolling upgrade.

DROP INDEX CONCURRENTLY IF EXISTS outbox_tenant_effective_lane_processing_idx;

CREATE INDEX CONCURRENTLY outbox_tenant_effective_lane_processing_idx
    ON outbox (
        tenant_id,
        (COALESCE(NULLIF(effect_lane, ''), destination)),
        lease_until
    )
    WHERE status = 'processing';
