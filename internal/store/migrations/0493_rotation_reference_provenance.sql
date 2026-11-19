ALTER TABLE secret_rotation_schedules
    ADD COLUMN reference_provider_type text NOT NULL DEFAULT '';

ALTER TABLE secret_rotation_schedule_tick_rows
    ADD COLUMN reference_provider_type text NOT NULL DEFAULT '';

ALTER TABLE secret_rotation_schedule_ticks
    ADD COLUMN current_reference_provider_type text,
    ADD COLUMN reference_view_version integer NOT NULL DEFAULT 0,
    ADD COLUMN safe_receipt jsonb,
    ADD COLUMN legacy_receipt_digest text NOT NULL DEFAULT '',
    ADD COLUMN safe_prefix_digest text NOT NULL DEFAULT '',
    ADD CONSTRAINT secret_rotation_schedule_tick_reference_view_version
        CHECK (reference_view_version IN (0, 1));

ALTER TABLE dynamic_secret_leases
    ADD COLUMN revocation_event_sequence bigint NOT NULL DEFAULT 0
    CHECK (revocation_event_sequence >= 0);
