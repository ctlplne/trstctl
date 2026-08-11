-- 0144_issuance_approval_authority.sql -- AUD-77 bounded, single-use legacy
-- issuance approval authority.
--
-- The original tables identify a request by (tenant, resource, action), but they
-- did not say when that authority stopped being valid or whether it had already
-- been used. Add those durable facts without rewriting historical rows. NULL on a
-- pre-0144 row deliberately means "legacy and non-authorizing"; only requests
-- opened by the upgraded store receive a live status and bounded expiry.

ALTER TABLE issuance_approval_requests
    ADD COLUMN expires_at timestamptz,
    ADD COLUMN status text;

ALTER TABLE issuance_approval_requests
    ADD CONSTRAINT issuance_approval_requests_status_chk
    CHECK (
        status IS NULL
        OR status IN ('pending', 'approved', 'denied', 'expired', 'superseded', 'consumed')
    ) NOT VALID;

ALTER TABLE issuance_approval_requests
    VALIDATE CONSTRAINT issuance_approval_requests_status_chk;
