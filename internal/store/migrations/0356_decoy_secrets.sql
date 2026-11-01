-- Q6: a decoy secret is an application secret registered as bait. Reading its
-- value through the served API raises an alert naming the reader; the first
-- reader is kept on the decoy for the investigation. Existing decoys keep their
-- kind and content, and none of them is a secret decoy.
ALTER TABLE honey_tokens DROP CONSTRAINT IF EXISTS honey_tokens_kind_check;
ALTER TABLE honey_tokens
    ADD CONSTRAINT honey_tokens_kind_check CHECK (kind IN ('native', 'aws', 'secret'));

ALTER TABLE honey_tokens
    ADD COLUMN IF NOT EXISTS secret_name text,
    ADD COLUMN IF NOT EXISTS trigger_subject text;

ALTER TABLE honey_tokens DROP CONSTRAINT IF EXISTS honey_tokens_aws_complete;
ALTER TABLE honey_tokens ADD CONSTRAINT honey_tokens_aws_complete CHECK (
    (kind IN ('native', 'secret') AND aws_account_config_id IS NULL AND aws_account_id IS NULL
     AND aws_access_key_id IS NULL AND aws_lease_id IS NULL AND aws_regions IS NULL
     AND aws_poll_interval_seconds IS NULL)
    OR
    (kind = 'aws' AND aws_account_config_id IS NOT NULL AND aws_account_id ~ '^[0-9]{12}$'
     AND aws_access_key_id IS NOT NULL AND aws_lease_id IS NOT NULL
     AND cardinality(aws_regions) BETWEEN 1 AND 32
     AND aws_poll_interval_seconds BETWEEN 60 AND 3600)
);

-- A secret decoy names exactly one stored secret; no other kind names one.
ALTER TABLE honey_tokens ADD CONSTRAINT honey_tokens_secret_name CHECK (
    (kind = 'secret') = (secret_name IS NOT NULL)
    AND (secret_name IS NULL OR length(secret_name) BETWEEN 1 AND 1024)
);
