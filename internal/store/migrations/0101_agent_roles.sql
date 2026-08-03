-- Agent roles on the fleet read model (epic A2).
--
-- The authority for an agent's capability is the SAN in the certificate it
-- presents — that is what the claim path reads, and it cannot be edited without
-- re-enrolling. This column is the projection of that fact, so the Agents page can
-- show an operator which of their agents is a host agent and which is a relay
-- without opening a certificate.
--
-- Because it is a projection and not the source of truth, nothing authorizes off
-- it. Writing 'network' into this column by hand grants nothing: the certificate
-- still says host, and the claim path still refuses the work.
--
-- Empty means the agent has not heartbeated since the upgrade, which is a
-- different thing from host-only and should read differently in the console.
--
-- online-safe: ADD COLUMN with a constant default is catalog-only in PostgreSQL
-- 11+ — no table rewrite.
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS roles text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN agents.roles IS
    'Projection of the capability SANs in the agent''s certificate (epic A2). Display only — the certificate authorizes, not this column.';
