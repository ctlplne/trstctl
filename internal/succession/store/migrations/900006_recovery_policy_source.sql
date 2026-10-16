-- A recovery policy is authority only when reconstructed from a durable event.
-- Existing rows have no source event and stay unavailable until the operator
-- reconfigures them through the supported API, CLI, or console.
ALTER TABLE pcas_recovery_policy ADD COLUMN source_sequence bigint NOT NULL DEFAULT 0;
