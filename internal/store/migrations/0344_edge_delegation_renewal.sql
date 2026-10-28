-- A220: an operator lets a segment's hosts renew their delegated edge CA over
-- the agent channel with fresh attestation, within renewal_window_days of
-- expiry (0 = the 7-day default). A renewed delegation names the one it
-- renewed; the old one stays valid until it expires. Existing policies start
-- with renewal off and existing delegations renewed from nothing.
ALTER TABLE edge_segment_policies
    ADD COLUMN IF NOT EXISTS renewal_enabled     boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS renewal_window_days integer NOT NULL DEFAULT 0
        CHECK (renewal_window_days BETWEEN 0 AND 29);

ALTER TABLE edge_delegations
    ADD COLUMN IF NOT EXISTS renewed_from uuid;
