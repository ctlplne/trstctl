-- A126: transit key lifecycle facts, projected from the event log.
--
-- One row per key version's create or rotate fact, keyed by the random fact ID the transit service saves with that
-- version's sealed material in transit_keyrings and uses as the event's ID. The key bytes never appear here or in the
-- log; this read model says which versions the log records, so the versions listing can say so. A subject erasure may
-- tokenize key_name in history; the fact ID, not the name, links a fact to its version.
CREATE TABLE IF NOT EXISTS transit_key_facts (
    tenant_id   uuid        NOT NULL,
    fact_id     text        NOT NULL CHECK (fact_id ~ '^tf-[0-9a-f]{32}$'),
    key_name    text        NOT NULL CHECK (key_name <> ''),
    kind        text        NOT NULL CHECK (kind IN ('aead', 'hmac', 'sign')),
    version     integer     NOT NULL CHECK (version > 0),
    event_type  text        NOT NULL CHECK (
        (event_type = 'transit.key.created' AND version = 1) OR
        (event_type = 'transit.key.rotated' AND version > 1)
    ),
    event_seq   bigint      NOT NULL CHECK (event_seq > 0),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, fact_id)
);
ALTER TABLE transit_key_facts ENABLE ROW LEVEL SECURITY;
ALTER TABLE transit_key_facts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS transit_key_facts_isolation ON transit_key_facts;
CREATE POLICY transit_key_facts_isolation ON transit_key_facts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON transit_key_facts TO trstctl_app;
