-- A prepared existing-CA import must return the same public CSR after a lost
-- response, restart or backup restore. Extend the already-global signer claim
-- with the exact pending event envelope; it remains a first-writer receiver,
-- never a second CA authority read model.
ALTER TABLE ca_signer_handle_claims
    ADD COLUMN preparation_issuer_sha256 char(64),
    ADD COLUMN preparation_parent_id uuid,
    ADD COLUMN preparation_purpose text,
    ADD COLUMN preparation_csr_pem text,
    ADD COLUMN preparation_event_id text,
    ADD COLUMN preparation_event_time timestamptz,
    ADD COLUMN preparation_event_actor jsonb,
    ADD COLUMN preparation_event_payload bytea,
    ADD COLUMN preparation_status text;

ALTER TABLE ca_signer_handle_claims
    ADD CONSTRAINT ca_signer_handle_preparation_complete_chk CHECK (
        (preparation_status IS NULL AND preparation_issuer_sha256 IS NULL
         AND preparation_parent_id IS NULL AND preparation_purpose IS NULL AND preparation_csr_pem IS NULL
         AND preparation_event_id IS NULL AND preparation_event_time IS NULL
         AND preparation_event_actor IS NULL AND preparation_event_payload IS NULL)
        OR
        (state = 'claimed' AND preparation_status IN ('pending', 'completed')
         AND preparation_issuer_sha256 ~ '^[0-9a-f]{64}$'
         AND preparation_purpose <> '' AND preparation_csr_pem <> ''
         AND preparation_event_id <> '' AND preparation_event_time IS NOT NULL
         AND preparation_event_actor IS NOT NULL
         AND octet_length(preparation_event_payload) > 0)
    );
