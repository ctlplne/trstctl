-- Disposable offsets into the authoritative event stream. These let a retired
-- host job resume bounded receipt lookup after a restart; they grant no authority.
ALTER TABLE outbox
    ADD COLUMN host_rotation_scan_generation text NOT NULL DEFAULT '',
    ADD COLUMN host_rotation_scan_through bigint NOT NULL DEFAULT 0 CHECK (host_rotation_scan_through >= 0),
    ADD COLUMN host_rotation_scan_next bigint NOT NULL DEFAULT 0 CHECK (host_rotation_scan_next >= 0),
    ADD COLUMN host_rotation_delivery_sequence bigint NOT NULL DEFAULT 0 CHECK (host_rotation_delivery_sequence >= 0),
    ADD COLUMN host_rotation_custody_sequence bigint NOT NULL DEFAULT 0 CHECK (host_rotation_custody_sequence >= 0),
    ADD COLUMN host_rotation_result_sequence bigint NOT NULL DEFAULT 0 CHECK (host_rotation_result_sequence >= 0);
