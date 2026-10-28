-- migrate: no-transaction
-- A225: prepare the named key without blocking existing intake writers.
DROP INDEX CONCURRENTLY IF EXISTS ticket_intake_schedules_named_key;
CREATE UNIQUE INDEX CONCURRENTLY ticket_intake_schedules_named_key
    ON ticket_intake_schedules (tenant_id, system, name);
