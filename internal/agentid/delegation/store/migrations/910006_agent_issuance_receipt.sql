-- Bind a queued AGID issuance receipt to one exact signer-minted credential.
-- Historical rows remain NULL: no receipt is invented for credentials issued
-- before this mapping existed. The event log retains the source binding.
ALTER TABLE agent_issuances
    ADD COLUMN issuance_id text;

CREATE UNIQUE INDEX agent_issuances_receipt_unique
    ON agent_issuances (tenant_id, issuance_id)
    WHERE issuance_id IS NOT NULL;
