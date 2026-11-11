-- SPDX-License-Identifier: BUSL-1.1
-- A201-L1: a dynamic-lease rotation schedule carries the TTL of the lease each
-- scheduled rotation issues. The TTL is part of the schedule's immutable upsert
-- event and is projected here; every existing schedule reads 0 (none of them
-- is a dynamic-lease schedule, which needs a TTL above zero).
ALTER TABLE secret_rotation_schedules
    ADD COLUMN IF NOT EXISTS ttl_seconds integer NOT NULL DEFAULT 0;
