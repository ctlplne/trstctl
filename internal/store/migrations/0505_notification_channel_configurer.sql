-- The event actor is the authority holder for a stored notification credential.
-- Old rows have no trustworthy configurer and fail closed at redemption until
-- an authorized principal saves the channel again.
ALTER TABLE notification_channels
    ADD COLUMN configured_by text NOT NULL DEFAULT '',
    ADD COLUMN configured_by_ref text NOT NULL DEFAULT '';
