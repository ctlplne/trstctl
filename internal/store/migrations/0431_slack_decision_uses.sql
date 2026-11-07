-- SPDX-License-Identifier: BUSL-1.1
-- A277: a Slack approver's use of a posted, trstctl-signed button decision is
-- recorded once beside the install states and link codes, so a replayed or
-- repeated press is refused.
ALTER TABLE slack_one_time_codes DROP CONSTRAINT IF EXISTS slack_one_time_codes_purpose_check;
ALTER TABLE slack_one_time_codes ADD CONSTRAINT slack_one_time_codes_purpose_check
    CHECK (purpose IN ('install', 'link', 'decision'));
