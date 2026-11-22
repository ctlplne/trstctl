-- SPDX-License-Identifier: BUSL-1.1
-- CR-020: bind each served token to its authenticated minter. The text is
-- operator-visible metadata; the opaque reference survives privacy erasure and
-- lets a pending member-offboard command deny delegated bearers immediately.
ALTER TABLE api_tokens
    ADD COLUMN minted_by text NOT NULL DEFAULT '',
    ADD COLUMN minted_by_ref char(64) NOT NULL DEFAULT '';
