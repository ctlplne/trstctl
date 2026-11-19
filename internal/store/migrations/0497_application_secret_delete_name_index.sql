-- SPDX-License-Identifier: BUSL-1.1
-- migrate: no-transaction
-- CR-060: retained delete receipts disambiguate the name after value purge.
CREATE INDEX CONCURRENTLY IF NOT EXISTS application_secret_delete_name_idx
    ON application_secret_mutation_receipts (tenant_id, secret_name)
    WHERE action = 'delete';
