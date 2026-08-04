-- 0114: per-host SPIFFE Workload API posture (epic B3).
--
-- The Workload API moved from the control plane onto the hosts, and an operator
-- needs to see which hosts are actually serving it. Before this the heartbeat's
-- inventory counters were decoded and discarded, so the console could show that
-- an agent was alive but nothing about what it was serving.
--
-- Three columns rather than one, because they answer three different questions
-- and collapsing them would lose the distinction that matters most:
--
--   workload_api_served     — is this host serving the socket at all
--   workload_api_svids      — has it actually issued anything
--   workload_api_reported_at — did it tell us recently, or is this stale
--
-- "Serving but never issued" is a healthy new host. "Serving and issued, last
-- reported six hours ago" is a host whose agent has stopped beating. Those need
-- different responses, and a single boolean would render them identically.

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS workload_api_served boolean NOT NULL DEFAULT false,
    -- Cumulative since the agent started, so it RESETS on restart. That is
    -- honest rather than convenient: the agent is the only thing that can count
    -- issuances, it does not persist across restarts, and a monotonic column
    -- the control plane maintained would be inventing history the host never
    -- reported.
    ADD COLUMN IF NOT EXISTS workload_api_svids bigint NOT NULL DEFAULT 0,
    -- NULL means this agent has never reported Workload API state at all —
    -- distinct from reporting "not serving". An agent too old to know about
    -- this feature must not read as one that turned it off.
    ADD COLUMN IF NOT EXISTS workload_api_reported_at timestamptz;

COMMENT ON COLUMN agents.workload_api_served IS
    'epic B3: whether this host agent is serving the SPIFFE Workload API on a local socket.';
COMMENT ON COLUMN agents.workload_api_svids IS
    'epic B3: SVIDs this host has issued since its agent started; resets on restart.';
COMMENT ON COLUMN agents.workload_api_reported_at IS
    'epic B3: when this agent last reported Workload API state; NULL means never (an older agent).';
