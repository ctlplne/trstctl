-- A175: a PKCS#11 edge key is recorded as hardware-attested only on its token's
-- own attestation. A segment policy pins its token vendors' attestation roots
-- and may require that attestation; a delegation records the vendor root it
-- verified to and what the attestation names (device serial, key PIN and touch
-- policies). Existing policies pin no token roots and require nothing;
-- existing delegations record no token attestation.
ALTER TABLE edge_segment_policies
    ADD COLUMN IF NOT EXISTS pkcs11_attestation_roots_pem text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN IF NOT EXISTS require_pkcs11_attestation  boolean NOT NULL DEFAULT false;

ALTER TABLE edge_delegations
    ADD COLUMN IF NOT EXISTS token_attestation_root_sha256  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS token_attestation_serial       text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS token_attestation_pin_policy   text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS token_attestation_touch_policy text NOT NULL DEFAULT '';

-- The custody tuple stays closed: a PKCS#11 key is hardware-attested only with
-- a recorded token attestation, and only a PKCS#11 key can carry one.
ALTER TABLE edge_delegations DROP CONSTRAINT IF EXISTS edge_delegations_custody_tuple_check;
ALTER TABLE edge_delegations
    ADD CONSTRAINT edge_delegations_custody_tuple_check
        CHECK (
            (key_provider = 'tpm2' AND key_storage = 'device_bound' AND NOT key_exportable
                AND custody_assurance = 'hardware_key_attested' AND token_attestation_root_sha256 = '')
            OR
            (key_provider = 'pkcs11' AND key_storage = 'pkcs11' AND NOT key_exportable
                AND ((custody_assurance = 'host_attested_operator_claim' AND token_attestation_root_sha256 = '')
                  OR (custody_assurance = 'hardware_key_attested' AND token_attestation_root_sha256 <> '')))
            OR
            (key_provider = 'software' AND key_storage = 'file' AND key_exportable
                AND custody_assurance = 'host_attested_software_exception' AND token_attestation_root_sha256 = '')
        );
