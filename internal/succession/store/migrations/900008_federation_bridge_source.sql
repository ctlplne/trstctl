-- An imported bridge is authority only when a verified source event can rebuild it.
-- Older API-side direct writes have no signed bridge result and are not served.
ALTER TABLE pcas_federation_bridge ADD COLUMN source_sequence bigint NOT NULL DEFAULT 0;
