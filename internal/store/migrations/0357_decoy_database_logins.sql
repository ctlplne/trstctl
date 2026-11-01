-- Q6: a decoy can be a PostgreSQL login minted by a tenant's dynamic-secret
-- provider. The decoy names the provider, the dynamic-secret lease that owns
-- the login, and the login role; the leader's watcher reads that role's own
-- database's session counter. Existing decoys keep their kind and content.
ALTER TABLE honey_tokens DROP CONSTRAINT IF EXISTS honey_tokens_kind_check;
ALTER TABLE honey_tokens
    ADD CONSTRAINT honey_tokens_kind_check CHECK (kind IN ('native', 'aws', 'secret', 'database'));

ALTER TABLE honey_tokens
    ADD COLUMN IF NOT EXISTS db_provider_id text,
    ADD COLUMN IF NOT EXISTS db_lease_id text,
    ADD COLUMN IF NOT EXISTS db_role text;

ALTER TABLE honey_tokens DROP CONSTRAINT IF EXISTS honey_tokens_aws_complete;
ALTER TABLE honey_tokens ADD CONSTRAINT honey_tokens_aws_complete CHECK (
    (kind IN ('native', 'secret', 'database') AND aws_account_config_id IS NULL AND aws_account_id IS NULL
     AND aws_access_key_id IS NULL AND aws_lease_id IS NULL AND aws_regions IS NULL
     AND aws_poll_interval_seconds IS NULL)
    OR
    (kind = 'aws' AND aws_account_config_id IS NOT NULL AND aws_account_id ~ '^[0-9]{12}$'
     AND aws_access_key_id IS NOT NULL AND aws_lease_id IS NOT NULL
     AND cardinality(aws_regions) BETWEEN 1 AND 32
     AND aws_poll_interval_seconds BETWEEN 60 AND 3600)
);

-- A database decoy names its provider, lease and login; no other kind does.
ALTER TABLE honey_tokens ADD CONSTRAINT honey_tokens_database_complete CHECK (
    CASE WHEN kind = 'database'
         THEN db_provider_id IS NOT NULL AND db_lease_id IS NOT NULL AND db_role IS NOT NULL
         ELSE db_provider_id IS NULL AND db_lease_id IS NULL AND db_role IS NULL
    END
);
