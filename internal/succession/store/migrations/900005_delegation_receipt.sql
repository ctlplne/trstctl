-- A scope is operator-visible as signer-confirmed only when its last applied
-- event carries the isolated signer's verifiable readback. Pre-upgrade rows
-- remain visible with no receipt and must be re-provisioned before use.
ALTER TABLE pcas_delegation_scope ADD COLUMN signer_receipt_json bytea;
ALTER TABLE pcas_delegation_scope ADD COLUMN source_sequence bigint NOT NULL DEFAULT 0;
