-- A5: which rollout ring an agent belongs to.
--
-- Split from 0120 rather than living beside the campaign table, for the reason
-- 0115/0116 were split: SCHEMA-002's tripwire regex spans a whole file, so an
-- ALTER ... ADD COLUMN sharing a file with any CREATE TABLE ... DEFAULT reads as
-- a value-changing migration. Splitting is the honest fix; loosening the regex
-- to make this file pass would weaken a guard that exists to catch real
-- backfills.
--
-- Ring assignment lives on the AGENT, not in a campaign-scoped table: whether a
-- box is safe to break first is a property of the box, not of any one rollout.

-- NULLABLE with no default, for the same reason 0112 and 0115 give: a NOT NULL
-- DEFAULT '' would WRITE a value into every existing agent row, and the content
-- harness is right to object. It would also be a lie in miniature — it stamps
-- every agent that predates rings with something that reads like a recorded
-- answer. NULL is the truth: nobody has placed this agent yet.
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS upgrade_ring text;

COMMENT ON COLUMN agents.upgrade_ring IS
    'canary | early | broad, or NULL for UNASSIGNED. NULL is never treated as broad: an agent nobody deliberately placed must not be swept into the largest ring automatically.';
