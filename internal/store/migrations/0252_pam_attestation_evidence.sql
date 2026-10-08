-- SPDX-License-Identifier: BUSL-1.1
-- New PAM sessions project verified, non-secret attestation facts from their
-- immutable start event. Historical sessions remain NULL: their old start
-- events did not retain the facts, so a migration must not invent them.

ALTER TABLE pam_sessions ADD COLUMN attestation jsonb;
