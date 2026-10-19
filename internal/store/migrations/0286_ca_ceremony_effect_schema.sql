-- The release first-writer fence must retain the event schema even after
-- transient payload bytes are scrubbed. Existing claims are v2.
ALTER TABLE ca_ceremony_effect_commands
    ADD COLUMN event_schema_version integer NOT NULL DEFAULT 2
    CHECK (event_schema_version IN (2, 3));
