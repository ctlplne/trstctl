-- G1-L1: who requested a dynamic-secret lease. The subject of the
-- authenticated principal whose request opened the lease, projected from the
-- dynsecret.lease.pending event's actor. Leases from before carry none: the
-- event log names their requester only in a non-reversible request binding.
-- The column holds a subject, so privacy export, erasure and retention cover
-- it as they cover a PAM session's requested_by.

ALTER TABLE dynamic_secret_leases
    ADD COLUMN IF NOT EXISTS requested_by text NOT NULL DEFAULT '';
