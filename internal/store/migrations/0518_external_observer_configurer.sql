-- Event-derived authority for outbound observer event signing. Legacy rows
-- have no trustworthy configurer and fail closed until an authorized re-save.
ALTER TABLE external_observers
    ADD COLUMN configured_by text NOT NULL DEFAULT '',
    ADD COLUMN configured_by_ref text NOT NULL DEFAULT '';
