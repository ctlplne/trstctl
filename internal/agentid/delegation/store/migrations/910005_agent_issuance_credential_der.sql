-- AGID issued credential public bytes (internal/agentid/delegation/store) - proprietary
-- Enterprise/Provider. The isolated signer returns only public credential material; this
-- additive projection column lets the control plane serve the issued credential for
-- offline relying-party verification without ever storing private key material.

ALTER TABLE agent_issuances
    ADD COLUMN IF NOT EXISTS credential_der bytea;
