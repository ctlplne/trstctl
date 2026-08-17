-- AGENT-RACE-001: agents historically kept PRIMARY KEY (id) beside UNIQUE
-- (tenant_id, id). Concurrent read-after-write and durable projections insert the
-- same row, and PostgreSQL may report the non-arbiter uniqueness constraint before
-- ON CONFLICT can converge the replay. Give both constraints the same
-- tenant-scoped key so every matching unique index is an arbiter for
-- ON CONFLICT (tenant_id, id).

-- online-safe: attach the already-valid 0189 index, with populated 0189/0190 row and FK proof before and after
ALTER TABLE agents
    DROP CONSTRAINT agents_pkey,
    ADD CONSTRAINT agents_pkey PRIMARY KEY
        USING INDEX agents_tenant_id_id_primary_uq;
