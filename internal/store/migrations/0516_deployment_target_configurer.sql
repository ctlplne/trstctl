-- A connector credential may be read only while the actor who authorized its
-- immutable destination revision can still read that tenant secret. Historical
-- revisions have no attributable actor and fail closed until reauthorized.
ALTER TABLE deployment_targets
    ADD COLUMN configured_by text NOT NULL DEFAULT '',
    ADD COLUMN configured_by_ref text NOT NULL DEFAULT '';

ALTER TABLE deployment_target_revisions
    ADD COLUMN configured_by text NOT NULL DEFAULT '',
    ADD COLUMN configured_by_ref text NOT NULL DEFAULT '';
