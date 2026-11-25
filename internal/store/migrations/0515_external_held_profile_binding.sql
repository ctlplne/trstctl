-- SPDX-License-Identifier: BUSL-1.1

-- A held external CA request can be approved long after the original outbox
-- intent is retained. Keep the admitted profile and requested identifiers in
-- its event-derived row so resume can refuse a different returned certificate.
ALTER TABLE external_ca_held_issues
    ADD COLUMN IF NOT EXISTS profile_binding_known boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS profile_name text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS profile_version integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS profile_digest text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS protocol text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS ip_addresses text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS email_addresses text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS uris text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS requested_ekus text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS subject_spki_sha256 text NOT NULL DEFAULT '';
