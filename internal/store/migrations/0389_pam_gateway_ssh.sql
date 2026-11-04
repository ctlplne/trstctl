-- A254 part 2: SSH sessions through the access gateway. A gateway-bound SSH
-- target pins the host keys the gateway accepts from it (SHA256 fingerprints,
-- as ssh-keygen -l prints them); a gateway session records the principal its
-- certificate names, because the gateway's own per-session key is certified
-- when the gateway claims the session, not when it is opened.
ALTER TABLE pam_targets
    ADD COLUMN IF NOT EXISTS host_key_fingerprints text[] NOT NULL DEFAULT '{}';

ALTER TABLE pam_sessions
    ADD COLUMN IF NOT EXISTS ssh_principal text NOT NULL DEFAULT '';
