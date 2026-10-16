-- Issuer registration is valid only when a durable PCAS source event can
-- rebuild it. Older direct-write rows require explicit re-registration.
ALTER TABLE pcas_issuer_authority ADD COLUMN source_sequence bigint NOT NULL DEFAULT 0;
