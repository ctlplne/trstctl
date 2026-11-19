-- SPDX-License-Identifier: BUSL-1.1
-- Older completion events can contain arbitrary provider text. Only projection
-- of a completion emitted by the new classifier grants display authority.
ALTER TABLE discovery_runs ADD COLUMN diagnostics_classified boolean NOT NULL DEFAULT false;
