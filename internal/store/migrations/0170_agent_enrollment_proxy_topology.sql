-- SPDX-License-Identifier: BUSL-1.1

-- A4 / AUD-22: one row per authenticated relay already exists in agents. Add
-- its measured enrollment-proxy topology and evidence there, rather than a
-- second identity table that could drift away from the certificate-bound agent.
-- Existing rows keep reported_at NULL: "old agent cannot report" is not the
-- same operational state as "current agent explicitly reports proxy off".
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS enrollment_proxy_serving boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS enrollment_proxy_segment text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS enrollment_proxy_public_url text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS enrollment_proxy_healthy_upstreams integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS enrollment_proxy_unhealthy_upstreams integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS enrollment_proxy_unknown_upstreams integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS enrollment_proxy_upstream_failures bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS enrollment_proxy_forwarded bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS enrollment_proxy_refused bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS enrollment_proxy_last_forwarded_at timestamptz,
    ADD COLUMN IF NOT EXISTS enrollment_proxy_last_failover_at timestamptz,
    ADD COLUMN IF NOT EXISTS enrollment_proxy_reported_at timestamptz;

ALTER TABLE agents
    ADD CONSTRAINT agents_enrollment_proxy_counts_nonnegative
    CHECK (
        enrollment_proxy_healthy_upstreams >= 0
        AND enrollment_proxy_unhealthy_upstreams >= 0
        AND enrollment_proxy_unknown_upstreams >= 0
        AND enrollment_proxy_upstream_failures >= 0
        AND enrollment_proxy_forwarded >= 0
        AND enrollment_proxy_refused >= 0
    );

COMMENT ON COLUMN agents.enrollment_proxy_segment IS
    'Operator-named dark segment reported by this certificate-bound relay.';
COMMENT ON COLUMN agents.enrollment_proxy_public_url IS
    'Stable HTTPS enrollment authority shared by redundant relays in the segment.';
COMMENT ON COLUMN agents.enrollment_proxy_last_forwarded_at IS
    'Latest durable proof that this relay completed an enrollment protocol response.';
COMMENT ON COLUMN agents.enrollment_proxy_last_failover_at IS
    'Latest durable proof that this relay changed control-plane endpoint after a transport failure.';
COMMENT ON COLUMN agents.enrollment_proxy_reported_at IS
    'NULL means this agent build never reported enrollment-proxy posture.';
