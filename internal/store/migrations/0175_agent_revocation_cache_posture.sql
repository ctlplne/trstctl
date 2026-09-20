-- SPDX-License-Identifier: BUSL-1.1

-- AUD-39 / R3: newest signed metadata-only CRL/OCSP cache posture from each
-- certificate-bound relay. Cached DER, issuer DER, and upstream URLs remain in
-- the segment; this projection carries only the operational facts the console
-- and API need. NULL reported_at means an older agent cannot report it.
ALTER TABLE agents
    ADD COLUMN revocation_caches jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN revocation_caches_statement text NOT NULL DEFAULT '',
    ADD COLUMN revocation_caches_signature bytea NOT NULL DEFAULT ''::bytea,
    ADD COLUMN revocation_caches_signer_fingerprint text NOT NULL DEFAULT '',
    ADD COLUMN revocation_caches_reported_at timestamptz;

ALTER TABLE agents
    ADD CONSTRAINT agents_revocation_caches_shape_check
        CHECK (jsonb_typeof(revocation_caches) = 'array'),
    ADD CONSTRAINT agents_revocation_caches_evidence_check
        CHECK (
            (revocation_caches_reported_at IS NULL
             AND revocation_caches = '[]'::jsonb
             AND revocation_caches_statement = ''
             AND octet_length(revocation_caches_signature) = 0
             AND revocation_caches_signer_fingerprint = '')
            OR
            (revocation_caches_reported_at IS NOT NULL
             AND revocation_caches_statement <> ''
             AND octet_length(revocation_caches_signature) > 0
             AND revocation_caches_signer_fingerprint ~ '^[0-9a-f]{64}$')
        );

COMMENT ON COLUMN agents.revocation_caches IS
    'Normalized per-segment/per-issuer CRL and OCSP cache metadata; never cached protocol bytes, issuer bytes, or upstream URLs.';
COMMENT ON COLUMN agents.revocation_caches_statement IS
    'Canonical tenant-and-agent-bound cache posture statement signed by the relay certificate key.';
COMMENT ON COLUMN agents.revocation_caches_signature IS
    'Detached cache posture signature; never credential or cached response material.';
COMMENT ON COLUMN agents.revocation_caches_reported_at IS
    'Agent-signed issued-at of the newest accepted cache posture; NULL means the agent cannot report it.';
