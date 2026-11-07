-- Cursor authority is projected from immutable queued/inverse/advance sources.
-- Legacy inline rotations retain no paged cursor or invented native progress.
ALTER TABLE service_account_rotations ADD COLUMN manifest_cursor jsonb;
ALTER TABLE service_account_rotations ADD COLUMN manifest_cursor_source_id text NOT NULL DEFAULT '';
ALTER TABLE service_account_rotations ADD COLUMN manifest_cursor_sequence bigint NOT NULL DEFAULT 0 CHECK(manifest_cursor_sequence>=0);
ALTER TABLE service_account_rotations ADD CONSTRAINT service_dependent_cursor_source_pair CHECK (
 (manifest_cursor IS NULL AND manifest_cursor_source_id='' AND manifest_cursor_sequence=0)
 OR (manifest_cursor IS NOT NULL AND manifest_cursor_source_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND manifest_cursor_sequence>0)
);
