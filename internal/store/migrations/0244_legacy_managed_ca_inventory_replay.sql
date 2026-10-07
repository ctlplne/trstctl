-- A v2 managed-CA mint retained its public leaf but older binaries projected
-- only the responder serial. This receipt bit distinguishes an exact inventory
-- projection from an old responder-only completion, even after later privacy
-- or certificate state changes. It is set only with successful event replay.
ALTER TABLE certificate_metadata_receipts
    ADD COLUMN legacy_inventory_projected boolean NOT NULL DEFAULT false;

-- This is a recovery cursor, not certificate state. Older binaries can advance
-- applied_seq without this cursor, so the next current boot inspects that tail.
ALTER TABLE projection_checkpoint
    ADD COLUMN legacy_managed_ca_inventory_checked_through bigint NOT NULL DEFAULT 0
    CHECK (legacy_managed_ca_inventory_checked_through >= 0);
