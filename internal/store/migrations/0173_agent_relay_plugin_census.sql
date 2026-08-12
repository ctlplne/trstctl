-- SPDX-License-Identifier: MPL-2.0

-- AUD-34 / E4: the latest signed, metadata-only census from each authenticated
-- network relay. The immutable agent.heartbeat v2 event is the authority; these
-- columns are its tenant-isolated read projection. NULL reported_at means an old
-- agent cannot report the feature. A signed empty JSON array is a current relay
-- explicitly reporting that it loaded no third-party modules.
ALTER TABLE agents
    ADD COLUMN relay_plugins jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN relay_plugins_statement text NOT NULL DEFAULT '',
    ADD COLUMN relay_plugins_signature bytea NOT NULL DEFAULT ''::bytea,
    ADD COLUMN relay_plugins_signer_fingerprint text NOT NULL DEFAULT '',
    ADD COLUMN relay_plugins_reported_at timestamptz;

ALTER TABLE agents
    ADD CONSTRAINT agents_relay_plugins_shape_check
        CHECK (jsonb_typeof(relay_plugins) = 'array'),
    ADD CONSTRAINT agents_relay_plugins_evidence_check
        CHECK (
            (relay_plugins_reported_at IS NULL
             AND relay_plugins = '[]'::jsonb
             AND relay_plugins_statement = ''
             AND octet_length(relay_plugins_signature) = 0
             AND relay_plugins_signer_fingerprint = '')
            OR
            (relay_plugins_reported_at IS NOT NULL
             AND relay_plugins_statement <> ''
             AND octet_length(relay_plugins_signature) > 0
             AND relay_plugins_signer_fingerprint ~ '^[0-9a-f]{64}$')
        );

COMMENT ON COLUMN agents.relay_plugins IS
    'Normalized metadata-only modules loaded by this relay: names, verified digest/publisher fingerprints, execution context, and effective grants.';
COMMENT ON COLUMN agents.relay_plugins_statement IS
    'Canonical tenant-and-agent-bound statement signed by the relay certificate key.';
COMMENT ON COLUMN agents.relay_plugins_signature IS
    'Detached signature over relay_plugins_statement; never module bytes or secret material.';
COMMENT ON COLUMN agents.relay_plugins_reported_at IS
    'Agent-signed issued-at of the newest accepted census; NULL means the agent cannot report it.';
