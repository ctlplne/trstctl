-- SPDX-License-Identifier: BUSL-1.1

-- seal_queued is the short, honest state between accepting an idempotent seal
-- request and the bounded outbox worker acquiring the cross-replica exclusive
-- tenant fence. Tenant crypto remains usable in this state only long enough for
-- the accepted HTTP result to become durable; the worker proves that wall before
-- committing sealed.
ALTER TABLE tenant_key_domains
    DROP CONSTRAINT tenant_key_domains_state_chk;

ALTER TABLE tenant_key_domains
    ADD CONSTRAINT tenant_key_domains_state_chk
    CHECK (state IN (
        'migrating', 'partial', 'unsealed', 'seal_queued', 'sealing', 'sealed',
        'unsealing', 'wrapper_unavailable', 'wrong_wrapper', 'corrupt'
    ));
