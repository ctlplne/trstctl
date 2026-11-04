-- N4: decoy key uses found in a CloudTrail trail's log files. An organization
-- trail's files hold every account in the organization, and a trail that logs
-- data events holds them too; LookupEvents returns neither.
-- aws_honey_trail_objects records each log file the monitor has read, by its
-- key, so an overlapping or repeated read never records a use twice; rows
-- older than four days are dropped as newer files are recorded (the monitor
-- reads only today's and yesterday's day folders). Projection of
-- honeytoken.aws.trail_object_scanned. aws_honey_uses gains the account whose
-- credentials made the call, the account whose trail logged it, CloudTrail's
-- category, and whether LookupEvents or a trail file found it; rows from
-- before carry no accounts or category and were found by LookupEvents.
CREATE TABLE IF NOT EXISTS aws_honey_trail_objects (
    tenant_id          uuid        NOT NULL,
    account_config_id  text        NOT NULL CHECK (account_config_id <> ''),
    object_key         text        NOT NULL CHECK (object_key <> '' AND length(object_key) <= 1024),
    size_bytes         bigint      NOT NULL CHECK (size_bytes >= 0),
    records            integer     NOT NULL CHECK (records >= 0),
    uses               integer     NOT NULL CHECK (uses >= 0),
    refused            text        NOT NULL DEFAULT '' CHECK (length(refused) <= 512),
    scanned_at         timestamptz NOT NULL,
    event_sequence     bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, account_config_id, object_key)
);
CREATE INDEX IF NOT EXISTS aws_honey_trail_objects_scanned_idx
    ON aws_honey_trail_objects (tenant_id, account_config_id, scanned_at DESC);
ALTER TABLE aws_honey_trail_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE aws_honey_trail_objects FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aws_honey_trail_objects_isolation ON aws_honey_trail_objects;
CREATE POLICY aws_honey_trail_objects_isolation ON aws_honey_trail_objects
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON aws_honey_trail_objects TO trstctl_app;

ALTER TABLE aws_honey_uses
    ADD COLUMN IF NOT EXISTS account_id text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS recipient_account_id text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS event_category text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS found_in text NOT NULL DEFAULT 'lookup'
        CHECK (found_in IN ('lookup', 'trail'));
