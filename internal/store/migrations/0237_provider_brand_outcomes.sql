-- A rejected custom-domain claim is retained in immutable Provider history but
-- must not poison authority replay or be mistaken for an applied brand.
ALTER TABLE provider_authority_projection_receipts
    ADD COLUMN outcome text NOT NULL DEFAULT 'applied'
    CHECK (outcome IN ('applied', 'rejected_domain'));
