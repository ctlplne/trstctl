-- Preserve the selected authority in the request projection. Historical
-- events lack these fields; empty means an unpinned legacy request, not proof
-- that its requester deliberately selected the built-in authority.
ALTER TABLE issuance_requests ADD COLUMN issuer_source text NOT NULL DEFAULT '';
ALTER TABLE issuance_requests ADD COLUMN issuer_id text NOT NULL DEFAULT '';
ALTER TABLE issuance_requests ADD COLUMN issuer_name text NOT NULL DEFAULT '';
