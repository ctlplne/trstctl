-- SPDX-License-Identifier: BUSL-1.1

-- Rotating a tenant key domain moves it from generation g to g+1 under a new
-- domain KEK. While the rotation runs, the next generation's wrapped KEK and
-- wrapper are part of the event-sourced snapshot, so a crash resumes with both
-- generations openable. rotated_at records the last completed rotation.
ALTER TABLE tenant_key_domains
    ADD COLUMN next_generation BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN next_wrapper_kind TEXT NOT NULL DEFAULT '',
    ADD COLUMN next_wrapper_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN next_wrapped_domain_kek BYTEA,
    ADD COLUMN rotated_at TIMESTAMPTZ;

ALTER TABLE tenant_key_domains
    DROP CONSTRAINT tenant_key_domains_state_chk;

ALTER TABLE tenant_key_domains
    ADD CONSTRAINT tenant_key_domains_state_chk
    CHECK (state IN (
        'migrating', 'partial', 'unsealed', 'seal_queued', 'sealing', 'sealed',
        'unsealing', 'rotating', 'wrapper_unavailable', 'wrong_wrapper', 'corrupt'
    ));

ALTER TABLE tenant_key_domains
    DROP CONSTRAINT tenant_key_domains_operation_kind_chk;

ALTER TABLE tenant_key_domains
    ADD CONSTRAINT tenant_key_domains_operation_kind_chk
    CHECK (operation_kind IN ('migrate', 'seal', 'unseal', 'rotate'));

-- The next generation is either wholly absent or wholly present, and always
-- exactly one generation ahead; a rotating domain always carries it.
ALTER TABLE tenant_key_domains
    ADD CONSTRAINT tenant_key_domains_next_generation_chk
    CHECK (
        (next_generation = 0
            AND next_wrapper_kind = ''
            AND next_wrapper_id = ''
            AND next_wrapped_domain_kek IS NULL)
        OR (next_generation = generation + 1
            AND length(btrim(next_wrapper_kind)) > 0
            AND length(btrim(next_wrapper_id)) > 0
            AND next_wrapped_domain_kek IS NOT NULL
            AND octet_length(next_wrapped_domain_kek) > 0)
    );

ALTER TABLE tenant_key_domains
    ADD CONSTRAINT tenant_key_domains_rotating_next_chk
    CHECK (state <> 'rotating' OR next_generation > 0);
