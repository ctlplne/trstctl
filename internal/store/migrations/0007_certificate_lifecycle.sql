-- 0007_certificate_lifecycle.sql — lifecycle automation (F6, sprint S4.5).
--
-- Adds the lifecycle bookkeeping the renewal/revocation/rotation/alerting engine
-- needs on the certificate inventory: a status, the rotation linkage to the
-- credential a cert supersedes, revocation metadata, and the timestamps that make
-- renewal and alerting idempotent (a superseded cert is not re-renewed; an
-- already-alerted cert is not re-alerted). RLS and grants are inherited from the
-- existing certificates table (0006).

ALTER TABLE certificates
    ADD COLUMN status            text NOT NULL DEFAULT 'active',
    ADD COLUMN replaces_id       uuid,
    ADD COLUMN revoked_at        timestamptz,
    ADD COLUMN revocation_reason text NOT NULL DEFAULT '',
    ADD COLUMN renewed_at        timestamptz,
    ADD COLUMN alerted_at        timestamptz;

-- The successor of a rotation points at the credential it replaces. The target
-- is always inserted in the same tenant by the lifecycle engine; clearing the
-- link if the predecessor is ever deleted keeps the row valid.
ALTER TABLE certificates
    ADD CONSTRAINT certificates_replaces_fk
    FOREIGN KEY (replaces_id) REFERENCES certificates (id) ON DELETE SET NULL;

-- Drives the renewal/alert scans: active certs ordered by expiry within a tenant.
CREATE INDEX certificates_status_expiry_idx ON certificates (tenant_id, status, not_after);
