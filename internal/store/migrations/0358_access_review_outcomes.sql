-- Q1: an access review now acts. A revoke decision records what trstctl did to
-- the reviewed credential (requested, manual or failed) and the item closes only
-- when the credential is observed revoked; a keep decision records the next
-- review date. Existing items keep their content: none has an outcome or a next
-- review date.
ALTER TABLE nhi_access_review_items
    ADD COLUMN IF NOT EXISTS revocation_status text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS revocation_detail text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS revocation_requested_at timestamptz,
    ADD COLUMN IF NOT EXISTS closed_at timestamptz,
    ADD COLUMN IF NOT EXISTS closing_evidence text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS next_review_at timestamptz;

ALTER TABLE nhi_access_review_items DROP CONSTRAINT IF EXISTS nhi_access_review_items_revocation_status;
ALTER TABLE nhi_access_review_items
    ADD CONSTRAINT nhi_access_review_items_revocation_status
        CHECK (revocation_status IN ('', 'requested', 'manual', 'failed', 'closed'));
