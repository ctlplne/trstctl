-- 900012_kem_data_keys.sql — PCAS KEM-wrapped data keys (A16).
--
-- One row is one tenant data key (DEK) that protects data outside trstctl,
-- registered as an envelope for an identity's KEM epoch: the KEM ciphertext
-- made for that epoch's public encapsulation key and the DEK sealed under the
-- derived key (AES-256-GCM). Only the isolated signer can open it. A re-wrap
-- moves every row of the predecessor epoch to the successor epoch through the
-- signer; the successor row carries the request that produced it and the
-- sequence of its receipt event. Rows are projections of immutable events.

CREATE TABLE pcas_kem_data_key (
    tenant_id            uuid    NOT NULL,
    identity_id          text    NOT NULL,
    epoch                bigint  NOT NULL,
    target_ref           text    NOT NULL,
    stage                text    NOT NULL,
    kem_ciphertext       bytea   NOT NULL,
    wrapped_dek          bytea   NOT NULL,
    dek_sha256           bytea   NOT NULL,
    ciphertext_sha256    bytea   NOT NULL,
    rewrapped_from_epoch bigint  NOT NULL DEFAULT 0,
    rewrap_request_id    text    NOT NULL DEFAULT '',
    readback_verified    boolean NOT NULL DEFAULT false,
    source_sequence      bigint  NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, identity_id, epoch, target_ref)
);

ALTER TABLE pcas_kem_data_key ENABLE ROW LEVEL SECURITY;
ALTER TABLE pcas_kem_data_key FORCE ROW LEVEL SECURITY;

CREATE POLICY pcas_kem_data_key_isolation ON pcas_kem_data_key
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX pcas_kem_data_key_stage_idx
    ON pcas_kem_data_key (tenant_id, identity_id, epoch, stage);

GRANT SELECT, INSERT, UPDATE, DELETE ON pcas_kem_data_key TO trstctl_app;

-- Per-stage data receipt counts: how many data keys the stage held at the
-- predecessor epoch and how many successor rows were written and read back.
ALTER TABLE pcas_rewrap_job ADD COLUMN data_keys integer NOT NULL DEFAULT 0;
ALTER TABLE pcas_rewrap_job ADD COLUMN data_keys_rewrapped integer NOT NULL DEFAULT 0;
-- Inventory snapshot and attestation carried by the accepted request (A16).
ALTER TABLE pcas_rewrap_job ADD COLUMN inventory_sequence bigint NOT NULL DEFAULT 0;
ALTER TABLE pcas_rewrap_job ADD COLUMN empty_inventory_attested boolean NOT NULL DEFAULT false;
