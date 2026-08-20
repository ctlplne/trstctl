-- A request decision and a successful issuance are different facts. Keep the
-- reviewer attribution intact when the real signer-backed result arrives.
ALTER TABLE issuance_requests
    ADD COLUMN IF NOT EXISTS issued_by text,
    ADD COLUMN IF NOT EXISTS issued_at timestamptz;
