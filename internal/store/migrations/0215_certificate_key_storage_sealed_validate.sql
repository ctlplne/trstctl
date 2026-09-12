-- Validation uses PostgreSQL's weaker validation lock after the short constraint
-- replacement transaction has committed. Existing allowed values remain valid.
ALTER TABLE certificates VALIDATE CONSTRAINT certificates_key_storage_known;
