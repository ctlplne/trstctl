-- 0017_identity_transitions.sql — lifecycle-history read model (SPINE-001).
--
-- The orchestrator's History/State previously reconstructed an identity's
-- lifecycle by replaying the WHOLE cross-tenant event log on every call
-- (O(total events) per read, plus cross-tenant I/O). This table is the
-- indexed, tenant-scoped read-model projection of the lifecycle transition
-- events (identity.issued, identity.deployed, …): the projector appends one
-- row per transition (the sole writer, AN-2), and History/State read it with a
-- single tenant-scoped, indexed query — O(this identity's transitions), never
-- touching another tenant's rows. The event log stays the source of truth; this
-- table is truncated and rebuilt from the log on a projection Rebuild (AN-2),
-- so it joins ReadModelTables rather than the backup set.
--
-- Per AN-1 the table carries tenant_id and isolation is enforced by row-level
-- security, not application code. seq is the appending event's stream sequence;
-- it is monotonic within a tenant and gives the deterministic transition order
-- a replay reproduces.

CREATE TABLE IF NOT EXISTS identity_transitions (
    tenant_id    uuid        NOT NULL,
    identity_id  uuid        NOT NULL,
    seq          bigint      NOT NULL,            -- appending event's stream sequence (ordering)
    from_state   text        NOT NULL,
    to_state     text        NOT NULL,
    event_type   text        NOT NULL,
    reason       text        NOT NULL DEFAULT '',
    occurred_at  timestamptz NOT NULL,           -- the event's own time (deterministic on rebuild)
    PRIMARY KEY (tenant_id, identity_id, seq)
);

-- The hot read path: an identity's transitions in order, confined to one tenant.
-- The PRIMARY KEY already covers (tenant_id, identity_id, seq) for that lookup;
-- this index serves the by-tenant scan used by State()/History() so the planner
-- never falls back to a sequential scan as the table grows.
CREATE INDEX IF NOT EXISTS identity_transitions_tenant_identity_seq_idx
    ON identity_transitions (tenant_id, identity_id, seq);

-- AN-1: isolation is enforced by row-level security. These rows are written by
-- the projector under the tenant's RLS context, so the policy needs WITH CHECK
-- as well as USING; an unset GUC is NULL, so every row is denied (fail closed).
ALTER TABLE identity_transitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_transitions FORCE  ROW LEVEL SECURITY;

CREATE POLICY identity_transitions_isolation ON identity_transitions
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_transitions TO trstctl_app;
