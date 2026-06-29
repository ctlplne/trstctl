-- migrate: no-transaction
-- online-safe: CONCURRENTLY avoids blocking writes on the live CRL/read-model tables.

CREATE INDEX CONCURRENTLY IF NOT EXISTS ca_crls_latest_artifact_idx
    ON ca_crls (
        tenant_id,
        ca_id,
        COALESCE(crl_kind, 'full'),
        COALESCE(shard_index, 0),
        crl_number DESC
    );

-- online-safe: CONCURRENTLY avoids blocking writes while delta CRL lookup becomes indexed.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ca_crls_latest_delta_idx
    ON ca_crls (tenant_id, ca_id, delta_base_number, crl_number DESC)
    WHERE crl_kind = 'delta';

-- online-safe: CONCURRENTLY avoids blocking writes; the hash expression is used for
-- stable shard planning when an operator has a very large revoked-serial set.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ca_issued_certs_revoked_hash_shard256_idx
    ON ca_issued_certs (
        tenant_id,
        ca_id,
        (mod(abs(hashtext(serial)::bigint), 256)),
        revoked_at
    )
    WHERE revoked_at IS NOT NULL;
