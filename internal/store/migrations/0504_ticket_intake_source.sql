-- SPDX-License-Identifier: BUSL-1.1

-- CR-002: immutable event-projected origin for automatic ticket decisions.
-- Legacy rows have no attested source and are intentionally excluded from
-- automated status reads and outbound work notes.
ALTER TABLE issuance_requests ADD COLUMN ticket_source text NOT NULL DEFAULT '';
CREATE INDEX issuance_requests_ticket_source_idx
    ON issuance_requests (tenant_id, ticket_source, ticket_ref)
    WHERE ticket_source <> '';
