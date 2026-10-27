-- An agent's clock against the control plane's, from its newest heartbeat that
-- carried a clock reading (agent.heartbeat schema 6): the agent's reading minus
-- the control plane's time when the heartbeat was recorded, in milliseconds, so
-- a positive value is an agent clock running ahead. Observation and alerting
-- only: the agent still times its own certificate renewal by its own clock.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS clock_skew_ms bigint;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS clock_skew_observed_at timestamptz;
