-- SPDX-License-Identifier: BUSL-1.1

-- A244-L4: the enrollment path that issued a certificate (api, acme, est,
-- scep, cmp, agent, ...), as the issuing front end named it to the profile
-- check. It is projected from certificate.recorded events (AN-2); empty means
-- unrecorded: a certificate issued before this column, or one that was
-- observed or imported rather than enrolled here. The column carries a
-- constant default (no rewrite), and its check is added NOT VALID: every
-- existing row holds the default the check admits.
ALTER TABLE certificates
    ADD COLUMN IF NOT EXISTS enrollment_protocol text NOT NULL DEFAULT '';
ALTER TABLE certificates
    DROP CONSTRAINT IF EXISTS certificates_enrollment_protocol_chk;
ALTER TABLE certificates
    ADD CONSTRAINT certificates_enrollment_protocol_chk
    CHECK (enrollment_protocol ~ '^[a-z0-9-]{0,32}$') NOT VALID;

-- The certificate read model orders every certificate fact through the same
-- statement and row metadata fences (0207/0312/0322): the enrollment path is
-- one of those facts.
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
    key_attestation,enrollment_protocol
ON certificates FOR EACH ROW EXECUTE FUNCTION certificate_metadata_order();

CREATE TRIGGER certificate_metadata_statement_order
BEFORE INSERT OR DELETE OR UPDATE OF id,tenant_id,owner_id,subject,sans,issuer,serial,
    fingerprint,key_algorithm,not_before,not_after,deployment_location,source,
    created_at,status,replaces_id,revoked_at,revocation_reason,renewed_at,
    issuance_idempotency_key,certificate_der,certificate_pem,issuance_response,
    issuance_request_binding,broker_issuance,key_origin,key_storage,key_exportable,
    key_generated_by,observed_by,observed_kind,last_seen_at,validity_anchor,
    issuing_external_ca_id,key_origin_derivation,key_origin_proof_event_id,
    key_attestation,enrollment_protocol
ON certificates FOR EACH STATEMENT EXECUTE FUNCTION certificate_metadata_statement_order();
