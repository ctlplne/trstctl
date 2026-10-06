-- A pending CA ceremony can be cancelled without deleting its approvals or
-- immutable audit history. The projector alone writes these read-model fields.
ALTER TABLE ca_key_ceremonies
    ADD COLUMN closed_at timestamptz,
    ADD COLUMN closed_by text,
    ADD COLUMN close_reason text,
    ADD COLUMN close_event_id text;
