-- A258-L1: a vaulted Active Directory account's credential check reads the
-- account's failed sign-ins and its lockout threshold before it signs in, and
-- one short of lockout signs in with nothing: its outcome is lockout_risk. The
-- status column's check admits the new class; existing rows hold the classes
-- 0398 admitted, which it still admits.

ALTER TABLE pam_account_health
    DROP CONSTRAINT IF EXISTS pam_account_health_status_check;

ALTER TABLE pam_account_health
    ADD CONSTRAINT pam_account_health_status_check
        CHECK (status IN ('healthy', 'rejected', 'expired', 'locked', 'unreachable', 'error', 'not_supported', 'lockout_risk')) NOT VALID;

ALTER TABLE pam_account_health
    VALIDATE CONSTRAINT pam_account_health_status_check;
