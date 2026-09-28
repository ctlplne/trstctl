-- A serial written by an older binary is not proof that the issuance recount
-- covered it. Preserve missing provenance across upgrades and binary rollbacks.
ALTER TABLE ca_issued_certs
    ADD COLUMN issuance_event_id text,
    ADD COLUMN issuance_event_type text,
    ADD CONSTRAINT ca_issued_event_provenance_shape CHECK (
        (issuance_event_id IS NULL AND issuance_event_type IS NULL)
        OR (issuance_event_id IS NOT NULL AND issuance_event_id <> ''
            AND issuance_event_type IS NOT NULL AND issuance_event_type IN (
                'certificate.recorded', 'ca.certificate.issued',
                'ca.endentity.issued', 'edge.delegation.issued'))
    );
