-- A258-L2: an emergency grant's notice is also addressed to each approver by
-- name when a notification channel addresses named recipients (the operator's
-- email channel with named_recipients). The grant records whom, projected from
-- pam.emergency.opened's notified_approvers; a grant opened before A258-L2, or
-- with no such channel, names none.

ALTER TABLE pam_emergency_grants
    ADD COLUMN IF NOT EXISTS notified_approvers text[] NOT NULL DEFAULT '{}';
