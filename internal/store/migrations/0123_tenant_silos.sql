-- L4: durable per-tenant silo placement and data residency.
--
-- Silo assignment was in memory. On restart every tenant reverted to the
-- default isolation model, SILENTLY — a customer who bought hard isolation got
-- it until the first deploy, and nothing in the running system would say so.
-- For a sovereignty feature that is the whole product failing quietly.
--
-- Residency is here rather than in a separate table because placement and
-- isolation are one decision: "this customer's data lives in this zone under
-- this model" is a single claim an auditor checks, and splitting it invites the
-- two halves to disagree.

CREATE TABLE IF NOT EXISTS tenant_silos (
    tenant_id       uuid PRIMARY KEY,
    slug            text NOT NULL DEFAULT '',
    -- The isolation model this tenant was SOLD. Empty means unset, which the
    -- router must read as the shared default rather than guessing an upgrade.
    isolation_model text NOT NULL DEFAULT '',
    -- The residency zone a tenant's data is pinned to. Empty means UNPINNED,
    -- and unpinned is never rendered as "compliant with any zone" — an absent
    -- pin is the absence of a guarantee, not a permissive one.
    residency_zone  text NOT NULL DEFAULT '',
    status          text NOT NULL DEFAULT 'active',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- AN-1: the row is keyed by tenant and confined to it. A tenant may read which
-- silo and zone it was placed in — that is what they are paying for — and the
-- served API exposes no route letting them change it.
ALTER TABLE tenant_silos ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_silos FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_silos_tenant_isolation ON tenant_silos;
CREATE POLICY tenant_silos_tenant_isolation ON tenant_silos
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_silos TO trstctl_app;
