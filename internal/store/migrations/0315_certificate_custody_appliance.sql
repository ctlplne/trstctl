-- An appliance can generate the subject key itself through its management API
-- at a relay's request; the control plane signs its CSR and never holds the
-- key, which stays in the appliance's key store. Record that origin and holder.
-- Extend validation without scanning certificate history while holding the
-- ALTER TABLE lock. The following migration validates existing rows separately.
ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_key_origin_known;
ALTER TABLE certificates ADD CONSTRAINT certificates_key_origin_known
    CHECK (key_origin IN ('', 'requester', 'host_agent', 'device', 'appliance', 'control_plane', 'signer')) NOT VALID;
ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_key_storage_known;
ALTER TABLE certificates ADD CONSTRAINT certificates_key_storage_known
    CHECK (key_storage IN ('', 'locked_memory', 'sealed_store', 'file', 'os_store', 'pkcs11', 'device_bound', 'service', 'kubernetes_secret', 'appliance')) NOT VALID;
