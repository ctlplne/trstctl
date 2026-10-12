-- An MDM bearer belongs to one network segment. Older schedules had only a
-- role requirement, so any same-tenant network relay could redeem it.
ALTER TABLE mdm_poll_schedules
    ADD COLUMN required_agent_id uuid;

COMMENT ON COLUMN mdm_poll_schedules.required_agent_id IS
    'Exact enrolled network relay that may claim and redeem this MDM schedule.';

-- A legacy enabled schedule cannot be safely dispatched until the operator
-- selects the relay that can reach its MDM. Preserve it for review.
UPDATE mdm_poll_schedules
   SET enabled = false,
       last_error = 'Disabled during exact-relay upgrade: select one enrolled network relay and re-enable.'
 WHERE enabled AND required_agent_id IS NULL;

ALTER TABLE mdm_poll_schedules
    ADD CONSTRAINT mdm_poll_enabled_requires_exact_relay
    CHECK (NOT enabled OR required_agent_id IS NOT NULL);

-- Unclaimed legacy intents must never outlive the change and redeem a bearer
-- through a role-only claim. A finished receipt remains in the event log.
UPDATE outbox
   SET status = 'failed',
       last_error = 'Unbound MDM job retired during exact-relay upgrade; review the schedule and queue a new read.'
 WHERE destination = 'mdm.sync' AND required_agent_id IS NULL AND status = 'pending';
