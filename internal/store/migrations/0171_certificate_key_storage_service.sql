-- A co-resident credential service (currently Envoy SDS) is a storage locus,
-- but it is not evidence of locked memory, a file, or an OS certificate store.
-- Giving it its own closed value keeps host-renewal receipts truthful.

ALTER TABLE certificates
    DROP CONSTRAINT IF EXISTS certificates_key_storage_known;

ALTER TABLE certificates
    ADD CONSTRAINT certificates_key_storage_known
    CHECK (key_storage IN ('', 'locked_memory', 'file', 'os_store', 'pkcs11', 'device_bound', 'service'));
