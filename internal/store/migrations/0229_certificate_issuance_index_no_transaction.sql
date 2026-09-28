-- migrate: no-transaction
-- Build the mint lookup without blocking writers to the existing receipt table.
-- An interrupted concurrent build can leave an invalid same-name index. Drop
-- only this unledgered attempt and rebuild before the runner records success.
DROP INDEX CONCURRENTLY IF EXISTS certificate_receipt_issuance_origin;
CREATE INDEX CONCURRENTLY certificate_receipt_issuance_origin
    ON certificate_metadata_receipts (tenant_id, issuance_fingerprint, event_sequence)
    WHERE issuance_status = 'mint';
