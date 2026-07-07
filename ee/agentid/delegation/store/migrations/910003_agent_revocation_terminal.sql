-- AGID terminal-revocation columns (ee/agentid/revoke, AGID-11) — proprietary
-- Enterprise/Provider. Version 910003 is the next value in the AGID extension high
-- band (>= 910000, above the AGID-10 effect ledger at 910002), so it cannot collide
-- with core or succession migration versions. This migration adds the ONE durable
-- column AGID-11 needs on top of the AGID-02/10 revocation schema: the timestamp at
-- which a directive reached the terminal `revoked-with-evidence` state (INV-A9), so
-- the interval monitor (claim 23) can decide, from a persisted ledger-derived fact,
-- whether the transition happened within the policy-defined interval.
--
-- terminal_at is the durable companion to the existing `terminal boolean` column:
-- terminal is the ledger FACT that every enqueued and follow-on job completed with
-- signed evidence; terminal_at records WHEN that fact was established (Unix seconds),
-- measured against the directive's own recorded start so an exceedance is a distinct,
-- deterministic determination. It is NULL until the terminal transition lands, and is
-- set exactly once (the terminal flip is idempotent). This is NOT a claim that an
-- already-issued short-TTL credential became unusable at terminal_at — the cascade
-- covers sessions/dependents and FUTURE issuance/renewal, expiry covers the
-- outstanding credential (HARNESS.md §1.5 note (b)); terminal_at times the LEDGER
-- fact only.
--
-- Forward-only by policy (docs/migrations.md, the succession/AGID-02/10 precedent):
-- the core migration runner records only applied versions and has no down-migration
-- path; recovery is restore-from-backup. Every statement here is additive.

-- created_at already stamps when the directive row was inserted (the transition
-- start reference the interval is measured from). terminal_at stamps when the
-- terminal state was reached; the difference is the observed completion interval.
ALTER TABLE agent_revocation_directives
    ADD COLUMN terminal_at bigint;
