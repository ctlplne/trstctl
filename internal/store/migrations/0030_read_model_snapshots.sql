-- Read-model snapshots (SPINE-007 / EXC-SCALE-01): a periodic, per-tenant capture
-- of the event-sourced read model together with the global event-stream offset it
-- covers, so a cold boot or a disaster restore can rehydrate the read model from
-- the latest snapshot and then replay ONLY the tail after it — turning startup from
-- O(lifetime events) into O(events since the snapshot).
--
-- The event log stays the SOURCE OF TRUTH (AN-2). A snapshot is purely an
-- optimization: it is fully reconstructible by a Rebuild() from sequence 0, and a
-- corrupt, missing, or stale snapshot is ignored in favor of a full replay. Nothing
-- reads a snapshot to ANSWER a query; the relational read model does that. The
-- snapshot only seeds that read model faster on boot.
--
-- Tenant scoping (AN-1): one snapshot row per tenant carries that tenant's
-- read-model rows as an opaque blob, under the SAME tenant_id + row-level security
-- as every other tenant table. The blob never crosses a tenant boundary — a
-- tenant's snapshot is written and read only with that tenant's RLS context, so a
-- compromised or buggy projector cannot rehydrate one tenant's rows into another.
--
-- covered_seq is the global JetStream stream sequence the snapshot is consistent
-- as-of: every event with sequence <= covered_seq is already reflected in the blob,
-- so boot restore sets the projection checkpoint to MIN(covered_seq across tenants)
-- and replays only what follows. format_version lets the blob shape evolve without
-- silently mis-decoding an older snapshot (a snapshot whose version the running
-- code does not understand is ignored, falling back to a full rebuild).
--
-- This is an additive, idempotent forward migration (CREATE ... IF NOT EXISTS): it
-- adds a new table and a fail-closed RLS policy, changes no existing row, and a
-- fresh/upgraded deployment with no snapshots simply boots via the existing
-- checkpoint catch-up (identical to before) until the first snapshot is written.

CREATE TABLE IF NOT EXISTS read_model_snapshots (
    tenant_id      uuid        NOT NULL,
    covered_seq    bigint      NOT NULL,
    format_version integer     NOT NULL DEFAULT 1,
    payload        jsonb       NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id)
);

-- Speeds the boot read of the lowest covered offset across tenants.
CREATE INDEX IF NOT EXISTS read_model_snapshots_covered_seq_idx
    ON read_model_snapshots (covered_seq);

-- Row-level security, FORCE-d and fail-closed (AN-1), exactly like the other
-- tenant tables: a session may touch only the snapshot of the tenant named in the
-- trstctl.tenant_id GUC. An unset GUC is NULL, so every row is denied (fail
-- closed). The owner/system role (which the boot restore and the snapshot worker
-- run as for the cross-tenant pass) bypasses RLS but always carries tenant_id
-- explicitly in its SQL, so a row can never land under the wrong tenant.
ALTER TABLE read_model_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE read_model_snapshots FORCE  ROW LEVEL SECURITY;

CREATE POLICY read_model_snapshots_isolation ON read_model_snapshots
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON read_model_snapshots TO trstctl_app;
