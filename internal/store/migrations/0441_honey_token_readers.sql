-- SPDX-License-Identifier: BUSL-1.1
-- Q6-L1: the readers of each secret decoy. A decoy raises one alert per
-- distinct reader; the alert's outbox row was the only record of that, and a
-- delivered row is reclaimed a day after delivery, so the same reader reading
-- again alerted again. Each reader is kept as its tenant-bound one-way privacy
-- reference (never its name) with its first and last read and how many reads
-- it made. Projected from honeytoken.triggered events that name a reader; a
-- subject erasure moves the subject's row to their placeholder's reference.
CREATE TABLE honey_token_readers (
 tenant_id uuid NOT NULL,
 honey_token_id uuid NOT NULL,
 reader_ref text NOT NULL CHECK (reader_ref ~ '^[0-9a-f]{64}$'),
 first_read_at timestamptz NOT NULL,
 last_read_at timestamptz NOT NULL,
 reads bigint NOT NULL CHECK (reads >= 1),
 PRIMARY KEY (tenant_id, honey_token_id, reader_ref),
 CHECK (first_read_at <= last_read_at)
);
ALTER TABLE honey_token_readers ENABLE ROW LEVEL SECURITY;
ALTER TABLE honey_token_readers FORCE ROW LEVEL SECURITY;
CREATE POLICY honey_token_readers_isolation ON honey_token_readers
 USING(tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
 WITH CHECK(tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON honey_token_readers TO trstctl_app;
