-- SPDX-License-Identifier: MPL-2.0
-- Name the byte format stored in every idempotency result row. A reader must
-- know whether result is an old opaque byte string or a tenant-bound sealed
-- container before it can safely return a replay.

ALTER TABLE idempotency_keys
    ADD COLUMN IF NOT EXISTS result_codec text;

-- Existing rows predate the codec column. Label them honestly as raw first;
-- the narrow historical dynamic-lease proof below upgrades only rows whose
-- exact command identity and container header prove a stronger format.
UPDATE idempotency_keys
   SET result_codec = 'raw-v0'
 WHERE result_codec IS NULL;

-- The old dynamic-secret API already stored CSL1 version-1 containers. Do not
-- guess from a byte prefix alone: the tenant, raw idempotency key, and
-- authenticated request binding must all name the exact completed issue
-- command. A copied row, a legacy-unbound command, or another CSL1 version
-- remains raw-v0 and is handled by the compatibility reader.
UPDATE idempotency_keys AS cached
   SET result_codec = 'sealed-dynamic-lease-v1'
  FROM dynamic_secret_operations AS operation
 WHERE cached.tenant_id = operation.tenant_id
   AND cached.key = operation.idempotency_key
   AND cached.request_binding = operation.request_binding
   AND cached.status = 'completed'
   AND operation.action = 'issue'
   AND operation.status = 'completed'
   AND cached.result IS NOT NULL
   AND substring(cached.result FROM 1 FOR 5) = decode('43534c3101', 'hex')
   AND cached.result_codec = 'raw-v0';

ALTER TABLE idempotency_keys
    ALTER COLUMN result_codec SET DEFAULT 'raw-v0';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'idempotency_keys'::regclass
           AND conname = 'idempotency_keys_result_codec_chk'
    ) THEN
        ALTER TABLE idempotency_keys
            ADD CONSTRAINT idempotency_keys_result_codec_chk
            CHECK (
                result_codec IS NOT NULL
                AND result_codec IN (
                    'raw-v0',
                    'sealed-row-v1',
                    'sealed-dynamic-lease-v1'
                )
            ) NOT VALID;
    END IF;
END
$$;

-- Validation scans without holding the long ACCESS EXCLUSIVE lock that a
-- direct SET NOT NULL check would need. PostgreSQL can then use the proven
-- constraint to install the final NOT NULL metadata wall quickly.
ALTER TABLE idempotency_keys
    VALIDATE CONSTRAINT idempotency_keys_result_codec_chk;

ALTER TABLE idempotency_keys
    ALTER COLUMN result_codec SET NOT NULL;
