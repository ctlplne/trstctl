-- CRL artifact metadata for CAP-REV-02. Existing rows stay valid: NULL crl_kind
-- is interpreted by the application as the legacy full CRL artifact.

ALTER TABLE ca_crls
    ADD COLUMN crl_kind text,
    ADD COLUMN shard_index integer,
    ADD COLUMN shard_count integer,
    ADD COLUMN delta_base_number bigint,
    ADD COLUMN parent_crl_number bigint,
    ADD COLUMN revoked_count integer;

ALTER TABLE ca_crls
    ADD CONSTRAINT ca_crls_kind_check
    CHECK (crl_kind IS NULL OR crl_kind IN ('full', 'shard', 'delta')) NOT VALID;

ALTER TABLE ca_crls
    ADD CONSTRAINT ca_crls_shard_bounds_check
    CHECK (
        shard_index IS NULL
        OR (
            shard_count IS NOT NULL
            AND shard_count > 0
            AND shard_index >= 0
            AND shard_index < shard_count
        )
    ) NOT VALID;

ALTER TABLE ca_crls
    ADD CONSTRAINT ca_crls_delta_base_check
    CHECK (delta_base_number IS NULL OR delta_base_number > 0) NOT VALID;

ALTER TABLE ca_crls
    ADD CONSTRAINT ca_crls_parent_number_check
    CHECK (parent_crl_number IS NULL OR parent_crl_number > 0) NOT VALID;

ALTER TABLE ca_crls
    ADD CONSTRAINT ca_crls_revoked_count_check
    CHECK (revoked_count IS NULL OR revoked_count >= 0) NOT VALID;
