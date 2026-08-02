-- CA calendar (H5): year-scale expiry alerting for CA authorities.
--
-- Nothing evaluated ca_authorities.not_after before this. Leaf expiry alerting
-- runs on 7/30/90-day windows, which is the right clock for a leaf and useless
-- for a root: replacing a trust anchor means distributing it to every relying
-- party first, so the warning has to arrive in months, not days.
--
-- horizon_alerted_months records the tightest threshold band (36/24/12/6/3) this
-- authority has already been alerted at. The scheduler alerts only when the
-- authority crosses into a TIGHTER band than the one recorded, which gives
-- re-alerting at each tightening rather than one alert ever or one per sweep.
-- NULL means never alerted.
--
-- Both columns are alert bookkeeping, the same projection-side annotation
-- category as certificates.alerted_at (see internal/store/lifecycle.go): they
-- record what was notified, not what the authority IS, so they are written
-- directly by the alerting transaction rather than event-sourced. A Rebuild()
-- resets them, which re-alerts once — harmless, and preferable to inventing a
-- lifecycle event for a notification receipt.

ALTER TABLE ca_authorities
    ADD COLUMN horizon_alerted_months integer
        CHECK (horizon_alerted_months IS NULL OR horizon_alerted_months >= 0),
    ADD COLUMN horizon_alerted_at timestamptz;

-- The scheduler's enumerator scans for authorities with a known expiry that are
-- still in service; the partial index keeps that scan off retired rows.
--
-- online-safe: ca_authorities holds one row per CA a tenant operates — roots and
-- intermediates, counted in single or low double digits even for a large estate,
-- because every one of them is a key ceremony someone performed. The ACCESS
-- EXCLUSIVE lock a plain index build takes is therefore measured in milliseconds
-- on a table that is never bulk-loaded, and keeping this in the transactional
-- migration means the column additions above and the index that serves them
-- cannot land half-applied. A concurrent build would need its own
-- no-transaction migration and could leave an INVALID index behind on failure —
-- a worse trade for a table this size (SCHEMA-006).
CREATE INDEX ca_authorities_horizon_idx
    ON ca_authorities (tenant_id, not_after)
    WHERE not_after IS NOT NULL AND status = 'active';
