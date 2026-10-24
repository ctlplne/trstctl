-- SPDX-License-Identifier: BUSL-1.1
-- A103: a scheduled report's dispatch (notification channels and one
-- ServiceNow ticket) and the dispatch snapshot each completed run made. Both
-- are nullable: NULL is the archive-only behavior every existing row keeps.
ALTER TABLE compliance_report_schedules ADD COLUMN dispatch jsonb;
ALTER TABLE compliance_report_runs ADD COLUMN dispatch jsonb;
