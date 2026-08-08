-- A5: the columns that let a campaign DRIVE upgrades rather than observe them.
--
-- Split from 0126 for the reason 0121 gives: SCHEMA-002's tripwire regex spans
-- a whole file, so an ALTER ... ADD COLUMN sharing a file with a CREATE TABLE
-- carrying DEFAULTs reads as a value-changing migration.
--
-- Every column here is NULLABLE with no default, and NULL is the honest value
-- for every existing row:
--   - a campaign that predates dispatch has no artifacts (nobody published
--     any), no dispatch round (nothing was ever dispatched) and no dispatched
--     ring. Stamping any of those would fabricate a record of a dispatch that
--     never happened.
--   - an outbox row enqueued before per-agent targeting existed demands no
--     particular agent, which is exactly what NULL means to the claim query.

-- required_agent_id narrows a job to ONE agent, the way required_agent_role
-- narrows to a capability. An agent.upgrade job is an instruction to a specific
-- machine to replace its own binary; a fleet-claimable row would hand agent A
-- the order meant for agent B, and the first sign would be the wrong box
-- restarting.
ALTER TABLE outbox
    ADD COLUMN IF NOT EXISTS required_agent_id uuid;

COMMENT ON COLUMN outbox.required_agent_id IS
    'When set, only this agent may claim the row (epic A5). NULL follows kind and role rules alone.';

-- artifacts is the operator-published download set for the campaign target
-- version: [{os, arch, url, sha256}]. NULL means the campaign is OBSERVE-ONLY —
-- it gates rings on versions it sees but dispatches nothing, which is the only
-- thing every campaign could do before this migration.
ALTER TABLE agent_upgrade_campaigns
    ADD COLUMN IF NOT EXISTS artifacts jsonb;

-- dispatch_round / dispatched_ring drive the self-healing dispatch loop: a ring
-- entry clears dispatched_ring, the dispatch event stamps it and bumps the
-- round, and the sweep dispatches whenever the two disagree. NULL round reads
-- as 0 (no round yet); NULL dispatched_ring reads as "the current ring has not
-- been dispatched".
ALTER TABLE agent_upgrade_campaigns
    ADD COLUMN IF NOT EXISTS dispatch_round integer;

ALTER TABLE agent_upgrade_campaigns
    ADD COLUMN IF NOT EXISTS dispatched_ring text;

COMMENT ON COLUMN agent_upgrade_campaigns.artifacts IS
    'Operator-published per-platform artifact list for the target version (epic A5). NULL = observe-only campaign: nothing is dispatched.';
COMMENT ON COLUMN agent_upgrade_campaigns.dispatch_round IS
    'Monotonic count of ring dispatches for this campaign (epic A5). NULL reads as 0.';
COMMENT ON COLUMN agent_upgrade_campaigns.dispatched_ring IS
    'The ring the current dispatch round was sent to (epic A5). NULL means the current ring has not been dispatched yet.';
