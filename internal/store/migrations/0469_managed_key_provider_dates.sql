-- A168-L3: a managed key records the provider's own dates — when the cloud
-- KMS created the key, and when it will destroy it once destruction is
-- scheduled — from the isolated signer's lifecycle results, so trstctl's
-- record carries the provider's dates rather than the moment its operation
-- completed. Nullable: keys from before this release, and providers that
-- report no dates, have none.
ALTER TABLE managed_keys
    ADD COLUMN IF NOT EXISTS provider_created_at  timestamptz,
    ADD COLUMN IF NOT EXISTS provider_deletion_at timestamptz;
