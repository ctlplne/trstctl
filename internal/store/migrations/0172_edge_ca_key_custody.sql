-- AUD-26 / AUD-123: make disconnected edge-CA custody explicit and replayable.
--
-- Existing B6 rows were minted only through the same-key TPM attestation lane,
-- so the backfill is truthful: TPM2, device-bound, non-exportable, and the CSR
-- key digest equals the attested key digest. New PKCS#11 and software lanes are
-- default-denied by each segment's allowed_key_providers array. Application
-- validation keeps that array to the closed provider vocabulary.

ALTER TABLE edge_segment_policies
    ADD COLUMN allowed_key_providers text[] NOT NULL DEFAULT ARRAY['tpm2']::text[];

ALTER TABLE edge_delegations
    ADD COLUMN csr_key_sha256 text NOT NULL DEFAULT '',
    ADD COLUMN key_provider text NOT NULL DEFAULT 'tpm2',
    ADD COLUMN key_storage text NOT NULL DEFAULT 'device_bound',
    ADD COLUMN key_exportable boolean NOT NULL DEFAULT false,
    ADD COLUMN custody_assurance text NOT NULL DEFAULT 'hardware_key_attested';

UPDATE edge_delegations
   SET csr_key_sha256 = attested_key_sha256
 WHERE csr_key_sha256 = '';

ALTER TABLE edge_delegations
    ADD CONSTRAINT edge_delegations_key_provider_check
        CHECK (key_provider IN ('tpm2', 'pkcs11', 'software')),
    ADD CONSTRAINT edge_delegations_key_storage_check
        CHECK (key_storage IN ('device_bound', 'pkcs11', 'file')),
    ADD CONSTRAINT edge_delegations_custody_assurance_check
        CHECK (custody_assurance IN (
            'hardware_key_attested',
            'host_attested_operator_claim',
            'host_attested_software_exception'
        )),
    ADD CONSTRAINT edge_delegations_custody_tuple_check
        CHECK (
            (key_provider = 'tpm2' AND key_storage = 'device_bound' AND NOT key_exportable
                AND custody_assurance = 'hardware_key_attested')
            OR
            (key_provider = 'pkcs11' AND key_storage = 'pkcs11' AND NOT key_exportable
                AND custody_assurance = 'host_attested_operator_claim')
            OR
            (key_provider = 'software' AND key_storage = 'file' AND key_exportable
                AND custody_assurance = 'host_attested_software_exception')
        );
