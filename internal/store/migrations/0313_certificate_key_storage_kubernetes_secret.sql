-- An in-cluster agent generates the key and writes it into a Kubernetes Secret
-- of type kubernetes.io/tls. Record that holder instead of calling it a file.
-- Extend validation without scanning certificate history while holding the
-- ALTER TABLE lock. The following migration validates existing rows separately.
ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_key_storage_known;
ALTER TABLE certificates ADD CONSTRAINT certificates_key_storage_known
    CHECK (key_storage IN ('', 'locked_memory', 'sealed_store', 'file', 'os_store', 'pkcs11', 'device_bound', 'service', 'kubernetes_secret')) NOT VALID;
