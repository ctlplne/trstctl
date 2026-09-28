-- Keep immutable mint facts with the event completion receipt. Inventory
-- provenance can change during discovery; revocation cannot undo a past mint.
-- NULL means a pre-upgrade receipt whose source history must be replayed.
ALTER TABLE certificate_metadata_receipts
    ADD COLUMN issuance_status text,
    ADD COLUMN issuance_fingerprint text,
    ADD COLUMN issuance_time timestamptz,
    ADD CONSTRAINT certificate_receipt_issuance_shape CHECK (coalesce((
        (issuance_status IS NULL AND issuance_fingerprint IS NULL AND issuance_time IS NULL)
        OR (issuance_status IN ('not_mint', 'unverifiable') AND issuance_fingerprint IS NULL AND issuance_time IS NULL)
        OR (issuance_status = 'mint' AND issuance_fingerprint IS NOT NULL
            AND issuance_fingerprint <> '' AND issuance_time IS NOT NULL)
    ), false));
-- A pre-upgrade serial registry may contain leaves with no retained public
-- issuance proof. Do not present that missing population as a verified zero.
-- NULL is deliberately accepted for a snapshot made before this column existed;
-- callers require IS TRUE. New registrations start in the current format.
ALTER TABLE tenants ADD COLUMN responder_issuance_history_known boolean DEFAULT true;
UPDATE tenants t SET responder_issuance_history_known=false
    WHERE EXISTS (SELECT 1 FROM ca_issued_certs c WHERE c.tenant_id=t.tenant_id);
