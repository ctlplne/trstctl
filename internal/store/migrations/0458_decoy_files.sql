-- Q6-O1: a decoy can be a file a host agent planted: an SSH private key
-- written where no file was, which nothing on the host has a reason to open.
-- The decoy names the host (its agent's certificate name), the file's path and
-- the fingerprint of the key's public half; the agent watches the file and
-- reports each open. Existing decoys keep their kind and content, and none of
-- them is a file decoy. The tenant/kind index (0236) serves the lookups.
ALTER TABLE honey_tokens DROP CONSTRAINT IF EXISTS honey_tokens_kind_check;
ALTER TABLE honey_tokens
    ADD CONSTRAINT honey_tokens_kind_check CHECK (kind IN ('native', 'aws', 'secret', 'database', 'file'));

ALTER TABLE honey_tokens
    ADD COLUMN IF NOT EXISTS file_host text,
    ADD COLUMN IF NOT EXISTS file_path text,
    ADD COLUMN IF NOT EXISTS file_key_fingerprint text;

ALTER TABLE honey_tokens DROP CONSTRAINT IF EXISTS honey_tokens_aws_complete;
ALTER TABLE honey_tokens ADD CONSTRAINT honey_tokens_aws_complete CHECK (
    (kind IN ('native', 'secret', 'database', 'file') AND aws_account_config_id IS NULL AND aws_account_id IS NULL
     AND aws_access_key_id IS NULL AND aws_lease_id IS NULL AND aws_regions IS NULL
     AND aws_poll_interval_seconds IS NULL)
    OR
    (kind = 'aws' AND aws_account_config_id IS NOT NULL AND aws_account_id ~ '^[0-9]{12}$'
     AND aws_access_key_id IS NOT NULL AND aws_lease_id IS NOT NULL
     AND cardinality(aws_regions) BETWEEN 1 AND 32
     AND aws_poll_interval_seconds BETWEEN 60 AND 3600)
);

-- A file decoy names its host, an absolute path and its key's fingerprint; no
-- other kind names any of them.
ALTER TABLE honey_tokens DROP CONSTRAINT IF EXISTS honey_tokens_file_complete;
ALTER TABLE honey_tokens ADD CONSTRAINT honey_tokens_file_complete CHECK (
    CASE WHEN kind = 'file'
         THEN file_host IS NOT NULL AND length(file_host) BETWEEN 1 AND 256
              AND file_path IS NOT NULL AND length(file_path) BETWEEN 2 AND 1024 AND left(file_path, 1) = '/'
              AND file_key_fingerprint IS NOT NULL AND file_key_fingerprint LIKE 'SHA256:%'
         ELSE file_host IS NULL AND file_path IS NULL AND file_key_fingerprint IS NULL
    END
);
