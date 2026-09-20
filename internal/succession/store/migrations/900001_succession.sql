-- PCAS succession store (internal/succession/store) — proprietary Enterprise/Provider.
-- Version 900001 is in the reserved extension high band (>= 900000) so it cannot
-- collide with core migration versions. Two tenant-scoped tables, both with
-- FORCE-d row-level security so cross-tenant access is denied (AN-1, claim 7).

-- Durable, queryable succession chain: one row per succession record.
CREATE TABLE succession_records (
    tenant_id         uuid   NOT NULL,
    identity_id       text   NOT NULL,
    epoch             bigint NOT NULL,
    predecessor_epoch bigint NOT NULL,
    predecessor_alg   text   NOT NULL,
    successor_alg     text   NOT NULL,
    successor_pub     bytea  NOT NULL,
    record            bytea  NOT NULL,   -- opaque encoded dual-signed record (PCAS-04)
    created_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, identity_id, epoch)
);

ALTER TABLE succession_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE succession_records FORCE ROW LEVEL SECURITY;

CREATE POLICY succession_records_isolation ON succession_records
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON succession_records TO trstctl_app;

-- Control-plane serving copy of each identity's current algorithm-epoch
-- high-water. This is a read/serving copy only; the signer's sealed floor
-- remains the authority (INV-3). Monotonicity here is defense in depth.
CREATE TABLE identity_algorithm_epoch (
    tenant_id   uuid   NOT NULL,
    identity_id text   NOT NULL,
    epoch       bigint NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, identity_id)
);

ALTER TABLE identity_algorithm_epoch ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_algorithm_epoch FORCE ROW LEVEL SECURITY;

CREATE POLICY identity_algorithm_epoch_isolation ON identity_algorithm_epoch
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_algorithm_epoch TO trstctl_app;
