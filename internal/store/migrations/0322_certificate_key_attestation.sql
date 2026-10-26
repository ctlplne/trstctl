-- SPDX-License-Identifier: BUSL-1.1

-- key_attestation retains the hardware attestation behind a device-bound
-- custody claim exactly as it was verified at issuance (the device's TPM
-- attestation and the binding whose SHA-256 it signed), so anyone holding the
-- operator's TPM roots can re-check the claim offline. It is projected from
-- certificate.custody.device_attested events (AN-2); NULL means no
-- device-bound claim was made.
ALTER TABLE certificates
    ADD COLUMN key_attestation JSONB;

ALTER TABLE certificates
    ADD CONSTRAINT certificates_key_attestation_chk
    CHECK (
        key_attestation IS NULL
        OR (jsonb_typeof(key_attestation) = 'object'
            AND key_origin = 'device'
            AND key_storage = 'device_bound'
            AND key_exportable = 'non_exportable')
    );

-- The certificate read model must order every certificate fact through the
-- same statement and row metadata fences (0207/0312): the device-bound claim's
-- evidence is one of those facts.
DROP TRIGGER certificate_metadata_order ON certificates;
DROP TRIGGER certificate_metadata_statement_order ON certificates;

CREATE TRIGGER certificate_metadata_order
BEFORE INSERT OR UPDATE OF id,tenant_id,owner_id,subject,sans,issuer,serial,
    fingerprint,key_algorithm,not_before,not_after,deployment_location,source,
    created_at,status,replaces_id,revoked_at,revocation_reason,renewed_at,
    issuance_idempotency_key,certificate_der,certificate_pem,issuance_response,
    issuance_request_binding,broker_issuance,key_origin,key_storage,key_exportable,
    key_generated_by,observed_by,observed_kind,last_seen_at,validity_anchor,
    issuing_external_ca_id,key_origin_derivation,key_origin_proof_event_id,
    key_attestation
ON certificates FOR EACH ROW EXECUTE FUNCTION certificate_metadata_order();

CREATE TRIGGER certificate_metadata_statement_order
BEFORE INSERT OR DELETE OR UPDATE OF id,tenant_id,owner_id,subject,sans,issuer,serial,
    fingerprint,key_algorithm,not_before,not_after,deployment_location,source,
    created_at,status,replaces_id,revoked_at,revocation_reason,renewed_at,
    issuance_idempotency_key,certificate_der,certificate_pem,issuance_response,
    issuance_request_binding,broker_issuance,key_origin,key_storage,key_exportable,
    key_generated_by,observed_by,observed_kind,last_seen_at,validity_anchor,
    issuing_external_ca_id,key_origin_derivation,key_origin_proof_event_id,
    key_attestation
ON certificates FOR EACH STATEMENT EXECUTE FUNCTION certificate_metadata_statement_order();
