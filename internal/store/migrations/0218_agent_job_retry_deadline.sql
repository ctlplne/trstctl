-- SPDX-License-Identifier: MPL-2.0
-- Host/relay failures need their own deadline. next_attempt_at belongs to the
-- control-plane dispatcher, which also defers jobs waiting for an agent.
-- A constant past default preserves existing jobs without rewriting the table.
ALTER TABLE outbox ADD COLUMN agent_next_attempt_at timestamptz NOT NULL
    DEFAULT '1970-01-01 00:00:00+00'::timestamptz;
