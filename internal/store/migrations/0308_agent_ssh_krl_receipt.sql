-- SPDX-License-Identifier: BUSL-1.1

-- A109: a host agent's newest signed receipt for the OpenSSH KRL its sshd
-- enforces, reported on agent.heartbeat v5 and read by the KRL fleet view.
-- NULL reported_at means the agent runs no KRL watcher or predates receipts;
-- nothing is invented for agents that never reported one.
ALTER TABLE agents
    ADD COLUMN ssh_krl jsonb,
    ADD COLUMN ssh_krl_statement text,
    ADD COLUMN ssh_krl_signature bytea,
    ADD COLUMN ssh_krl_signer_fingerprint text,
    ADD COLUMN ssh_krl_reported_at timestamptz;

ALTER TABLE agents
    ADD CONSTRAINT agents_ssh_krl_shape_check
        CHECK (ssh_krl IS NULL OR jsonb_typeof(ssh_krl) = 'object');
