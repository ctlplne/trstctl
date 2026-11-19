-- SPDX-License-Identifier: BUSL-1.1
-- Existing or old-writer reservations have no proof of whether an append was
-- attempted. A current writer records false explicitly when claiming a fence.
-- The rotation worker marks its exact fence true before sending an authorized
-- rollback publication.
ALTER TABLE application_secret_mutation_fences ADD COLUMN rollback_publication_authorized boolean;
