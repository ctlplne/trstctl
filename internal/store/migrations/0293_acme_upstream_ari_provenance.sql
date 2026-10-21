-- A51: a discovered external leaf, matched to a configured ACME authority by
-- its Authority Key Identifier, gets the same upstream ARI poll as a leaf the
-- authority issued through trstctl. The row records which binding admitted it,
-- because the two are checked differently on every delivery: an authenticated
-- issuer is a certificate fact; an issuer key id is an operator declaration.
-- Rebuilt from the request/observation events; the default names the only
-- provenance older events could have had. Online-safe: a defaulted column add.
ALTER TABLE acme_upstream_ari
    ADD COLUMN provenance text NOT NULL DEFAULT 'authenticated_issuer'
        CHECK (provenance IN ('authenticated_issuer', 'issuer_key_id'));
