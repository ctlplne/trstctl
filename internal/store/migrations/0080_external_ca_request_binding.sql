-- 0080_external_ca_request_binding.sql -- preserve the authenticated external-CA
-- command and complete public certificate chain after bounded HTTP/outbox caches
-- are reclaimed. These columns are projections of certificate.recorded events;
-- they are not a second source of business truth.

ALTER TABLE certificates
    ADD COLUMN IF NOT EXISTS issuance_request_binding text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS certificate_pem bytea NOT NULL DEFAULT '\x',
    ADD COLUMN IF NOT EXISTS issuance_response bytea NOT NULL DEFAULT '\x';
