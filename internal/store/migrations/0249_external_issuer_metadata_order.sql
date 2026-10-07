-- External issuer provenance changes the certificate read model and must use
-- the same statement and row metadata-order fences as other certificate facts.
-- Keep 0247 immutable: upgrades that already ran it receive this trigger fix.
DROP TRIGGER certificate_metadata_order ON certificates;
DROP TRIGGER certificate_metadata_statement_order ON certificates;

CREATE TRIGGER certificate_metadata_order
BEFORE INSERT OR UPDATE OF id,tenant_id,owner_id,subject,sans,issuer,serial,
    fingerprint,key_algorithm,not_before,not_after,deployment_location,source,
    created_at,status,replaces_id,revoked_at,revocation_reason,renewed_at,
    issuance_idempotency_key,certificate_der,certificate_pem,issuance_response,
    issuance_request_binding,broker_issuance,key_origin,key_storage,key_exportable,
    key_generated_by,observed_by,observed_kind,last_seen_at,validity_anchor,
    issuing_external_ca_id
ON certificates FOR EACH ROW EXECUTE FUNCTION certificate_metadata_order();

CREATE TRIGGER certificate_metadata_statement_order
BEFORE INSERT OR DELETE OR UPDATE OF id,tenant_id,owner_id,subject,sans,issuer,serial,
    fingerprint,key_algorithm,not_before,not_after,deployment_location,source,
    created_at,status,replaces_id,revoked_at,revocation_reason,renewed_at,
    issuance_idempotency_key,certificate_der,certificate_pem,issuance_response,
    issuance_request_binding,broker_issuance,key_origin,key_storage,key_exportable,
    key_generated_by,observed_by,observed_kind,last_seen_at,validity_anchor,
    issuing_external_ca_id
ON certificates FOR EACH STATEMENT EXECUTE FUNCTION certificate_metadata_statement_order();
