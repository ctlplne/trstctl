-- AUD-28: network and SSH discovery are relay-owned commands. Persist the
-- queue-time binding and the signed result's executor so replay and the console
-- do not infer where a scan ran from mutable source configuration.

-- online-safe: every NOT NULL addition has a constant default, which is a
-- catalog-only operation on PostgreSQL 14+; nullable agent selectors do not
-- rewrite the table. The populated N-1 -> N harness proves old rows retain
-- their exact content and acquire the fail-closed control_plane/empty defaults.
ALTER TABLE discovery_runs
    ADD COLUMN execution text NOT NULL DEFAULT 'control_plane',
    ADD COLUMN segment text NOT NULL DEFAULT '',
    ADD COLUMN required_agent_role text NOT NULL DEFAULT '',
    ADD COLUMN required_agent_id uuid,
    ADD COLUMN executed_by_agent_id uuid,
    ADD COLUMN blocked integer NOT NULL DEFAULT 0;

ALTER TABLE discovery_runs
    ADD CONSTRAINT discovery_runs_execution_check
        CHECK (execution IN ('control_plane', 'relay')),
    ADD CONSTRAINT discovery_runs_agent_role_check
        CHECK (required_agent_role IN ('', 'network')),
    ADD CONSTRAINT discovery_runs_blocked_check
        CHECK (blocked >= 0),
    ADD CONSTRAINT discovery_runs_required_agent_fk
        FOREIGN KEY (tenant_id, required_agent_id)
        REFERENCES agents (tenant_id, id),
    ADD CONSTRAINT discovery_runs_executed_agent_fk
        FOREIGN KEY (tenant_id, executed_by_agent_id)
        REFERENCES agents (tenant_id, id);

COMMENT ON COLUMN discovery_runs.execution IS
    'Immutable queue-time executor boundary: relay for network/SSH, control_plane for explicit local connectors.';
COMMENT ON COLUMN discovery_runs.executed_by_agent_id IS
    'Agent identity from the verified mTLS receipt that produced the terminal relay result.';
