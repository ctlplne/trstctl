-- AUD-108: bind every dynamic-secret command and retained provider result to the
-- tenant registration that created it. The shared application-secret epoch is
-- the registration authority because tenant offboarding already deletes it and
-- PostgreSQL backup/restore already treats it as independent command state.

ALTER TABLE dynamic_secret_leases
    ADD COLUMN tenant_epoch text NOT NULL DEFAULT '',
    ADD COLUMN preparation_digest text NOT NULL DEFAULT '',
    ADD COLUMN prepared_at timestamptz,
    ADD COLUMN credential_digest text NOT NULL DEFAULT '',
    ADD COLUMN revocation_completed_at timestamptz;

ALTER TABLE dynamic_secret_operations
    ADD COLUMN tenant_epoch text NOT NULL DEFAULT '';

-- A tenant can have old dynamic-secret rows without ever having used the newer
-- application-secret API. Seed one shared registration epoch, then bind every
-- inherited lease, operation, and still-retained outbox command to it.
INSERT INTO application_secret_tenant_epochs (tenant_id, epoch_id)
SELECT DISTINCT tenant_id, gen_random_uuid()
  FROM (
      SELECT tenant_id FROM dynamic_secret_leases
      UNION
      SELECT tenant_id FROM dynamic_secret_operations
  ) AS dynamic_tenants
ON CONFLICT (tenant_id) DO NOTHING;

UPDATE dynamic_secret_leases AS lease
   SET tenant_epoch = epoch.epoch_id::text
  FROM application_secret_tenant_epochs AS epoch
 WHERE epoch.tenant_id = lease.tenant_id;

UPDATE dynamic_secret_operations AS operation
   SET tenant_epoch = epoch.epoch_id::text
  FROM application_secret_tenant_epochs AS epoch
 WHERE epoch.tenant_id = operation.tenant_id;

-- Preserve every replay proof that is still derivable. PostgreSQL's built-in
-- sha256(bytea) produces the same bytes as internal/crypto.SHA256Hex. Rows whose
-- terminal transition already cleared ciphertext deliberately keep an empty
-- digest: application replay treats that as unprovable and fails closed instead
-- of blessing the first retained candidate seen after upgrade.
UPDATE dynamic_secret_leases
   SET preparation_digest = encode(sha256(sealed_preparation), 'hex')
 WHERE octet_length(sealed_preparation) > 0;

UPDATE dynamic_secret_leases
   SET credential_digest = encode(sha256(sealed_credential), 'hex')
 WHERE octet_length(sealed_credential) > 0;

UPDATE dynamic_secret_leases
   SET revocation_completed_at = updated_at
 WHERE revocation_status = 'completed';

-- The outbox is part of the external command identity. Upgrade retained legacy
-- payloads and keys in place so a replayed v1 event and a warm database still
-- converge on one epoch-bound worker command. Prefix the new first JSON field
-- without a jsonb round trip: jsonb would reorder/reformat the old object and
-- break the byte-exact Go encoder identity used by replay validation.
UPDATE outbox AS queued
   SET payload = convert_to(
           '{"tenant_epoch":' || to_json(lease.tenant_epoch)::text || ',' ||
               substr(convert_from(queued.payload, 'UTF8'), 2),
           'UTF8'),
       idempotency_key = 'dynsecret.issue:' || lease.tenant_epoch || ':' || lease.id
  FROM dynamic_secret_leases AS lease
 WHERE queued.tenant_id = lease.tenant_id
   AND queued.id = lease.issue_outbox_id
   AND queued.destination = 'dynsecret.issue';

UPDATE outbox AS queued
   SET payload = convert_to(
           '{"tenant_epoch":' || to_json(lease.tenant_epoch)::text || ',' ||
               substr(convert_from(queued.payload, 'UTF8'), 2),
           'UTF8'),
       idempotency_key = 'dynsecret.revoke:' || lease.tenant_epoch || ':' || lease.id
  FROM dynamic_secret_leases AS lease
 WHERE queued.tenant_id = lease.tenant_id
   AND queued.id = lease.revoke_outbox_id
   AND queued.destination = 'dynsecret.revoke';

ALTER TABLE dynamic_secret_leases
    ALTER COLUMN tenant_epoch DROP DEFAULT,
    ADD CONSTRAINT dynamic_secret_leases_tenant_epoch_nonempty_chk
        CHECK (tenant_epoch <> ''),
    ADD CONSTRAINT dynamic_secret_leases_preparation_digest_chk
        CHECK (preparation_digest = '' OR preparation_digest ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT dynamic_secret_leases_credential_digest_chk
        CHECK (credential_digest = '' OR credential_digest ~ '^[0-9a-f]{64}$');

ALTER TABLE dynamic_secret_operations
    ALTER COLUMN tenant_epoch DROP DEFAULT,
    ADD CONSTRAINT dynamic_secret_operations_tenant_epoch_nonempty_chk
        CHECK (tenant_epoch <> '');

-- Migration 0187 builds the two populated-table lookup indexes online, after
-- this transactional backfill has installed every tenant epoch.

COMMENT ON COLUMN dynamic_secret_leases.tenant_epoch IS
    'Tenant registration epoch that owns this lease; old epochs are inert after offboard/re-registration.';
COMMENT ON COLUMN dynamic_secret_leases.preparation_digest IS
    'SHA-256 of the canonical sealed PreparedProvider input, retained after ciphertext cleanup for exact replay.';
COMMENT ON COLUMN dynamic_secret_leases.credential_digest IS
    'SHA-256 of the canonical sealed provider result, retained after revocation cleanup for exact replay.';
COMMENT ON COLUMN dynamic_secret_operations.tenant_epoch IS
    'Tenant registration epoch that owns this authenticated lifecycle command.';
