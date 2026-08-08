-- Dual-consent (two-person control) for provider break-glass grants (epic L4).
--
-- A break-glass grant used to become active on a SINGLE consent. Sovereign-grade
-- tenant access requires two-person control: two DISTINCT approvers, neither the
-- requester, must consent before the provider can read into a customer's
-- tenancy. These columns hold the second approver's consent; a grant is active
-- only once both consented_at and consented_at_2 are set (the plane enforces the
-- distinctness and requester-exclusion rules).
--
-- Pure shape, no backfill: both columns are added NULLable, so existing rows
-- carry a NULL second consent and read back (COALESCE) as no co-approver. A grant
-- that was merely singly-consented under the old single-consent rule is therefore
-- now correctly "awaiting co-consent" rather than silently active — a tightening,
-- and the safe direction for emergency tenant access.

ALTER TABLE provider_breakglass_grants
    ADD COLUMN consented_at_2 timestamptz,
    ADD COLUMN consented_by_2 text;
