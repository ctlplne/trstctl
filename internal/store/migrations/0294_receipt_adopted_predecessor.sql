-- A45: a host agent's first deploy to a target may adopt the pair it found
-- installed there as the rollback predecessor. The agent reports that adopted
-- leaf's fingerprint inside its signed receipt; the receipt projection keeps it
-- here so the control plane can name a predecessor it never delivered. Rebuilt
-- from connector.delivery.recorded events; the default is the only value a
-- receipt written before this column could have carried. Online-safe: a
-- defaulted column add.
ALTER TABLE connector_delivery_receipts
    ADD COLUMN adopted_predecessor_fingerprint text NOT NULL DEFAULT '';
