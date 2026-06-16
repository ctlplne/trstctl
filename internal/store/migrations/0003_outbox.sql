-- Outbox (AN-6): any call out (upstream CA, connector, webhook, notification) is
-- recorded here in the SAME transaction as the state change that triggers it. A
-- separate dispatch worker performs the call, giving at-least-once delivery; the
-- recorded idempotency_key lets the receiver collapse retries to one effect.
-- Per AN-1 the table carries tenant_id and is confined by row-level security.
CREATE TABLE outbox (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       uuid NOT NULL,
    destination     text NOT NULL,
    payload         bytea NOT NULL,
    idempotency_key text NOT NULL,
    status          text NOT NULL DEFAULT 'pending',
    attempts        integer NOT NULL DEFAULT 0,
    last_error      text,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    delivered_at    timestamptz
);

-- AN-1: isolation is enforced by row-level security. Entries are enqueued under
-- RLS (inside the triggering tenant transaction), so the policy needs WITH CHECK
-- as well as USING. The dispatch worker is a system operation and reads across
-- tenants via the pool (RLS-bypassing), like the projection workers.
ALTER TABLE outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox FORCE ROW LEVEL SECURITY;

-- A session may touch only its current tenant's entries; an unset GUC is NULL, so
-- the policy denies every row (fail closed).
CREATE POLICY outbox_isolation ON outbox
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- The dispatcher claims due, undelivered work; a partial index keeps that scan
-- cheap as delivered rows accumulate.
CREATE INDEX outbox_due_idx ON outbox (next_attempt_at) WHERE status = 'pending';

GRANT SELECT, INSERT, UPDATE ON outbox TO trstctl_app;
