-- Ownership depth: the application/service model (epic I1).
--
-- The owner record was four business fields — kind, name, email, tenant. That is
-- enough to send an expiry notification and nothing else, and it is the reason
-- "who owns this certificate" has been answerable while "what breaks if it
-- expires, and who else needs telling" has not.
--
-- All five columns are NULLABLE with no default. An estate that has been running
-- for years has owners nobody can retroactively classify, and a NOT NULL with a
-- placeholder default would fabricate an application id for every one of them —
-- turning "we do not know" into a value that reads like an answer. Unknown has to
-- stay distinguishable from known-and-empty, because the unowned queue this epic
-- adds is built entirely on that distinction.

ALTER TABLE owners
    -- application_id is the key an operator's CMDB already uses. Text rather than
    -- a foreign key: the authority for it lives outside trstctl, and a constraint
    -- here would make importing an estate fail on rows whose application was
    -- retired before the import ran.
    ADD COLUMN IF NOT EXISTS application_id text,
    ADD COLUMN IF NOT EXISTS service        text,
    ADD COLUMN IF NOT EXISTS business_unit  text,
    -- environment is deliberately unconstrained. Every estate names these
    -- differently (prod/production/prd), and a CHECK would reject the operator's
    -- own vocabulary in favour of ours.
    ADD COLUMN IF NOT EXISTS environment    text,
    -- escalation_chain is the STORED chain, distinct from the computed approver
    -- snapshot. The snapshot answers "who could approve this right now"; the
    -- chain answers "who do I wake at 3am, and in what order" — a question the
    -- approver graph cannot answer because it is about responsibility, not
    -- permission.
    ADD COLUMN IF NOT EXISTS escalation_chain jsonb,
    -- ownership_verified_at supports the verification cadence. NULL means never
    -- attested, which is a different and more urgent state than attested-long-ago.
    ADD COLUMN IF NOT EXISTS ownership_verified_at timestamptz;
