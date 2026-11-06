-- A267: freeze native rotation authority and retain one sealed preparation.
ALTER TABLE secret_static_rotation_commands
    ADD COLUMN provider_binding text NOT NULL DEFAULT '',
    ADD COLUMN sealed_preparation bytea,
    ADD CONSTRAINT secret_static_rotation_provider_binding_check
        CHECK (provider_binding = '' OR provider_binding ~ '^[0-9a-f]{64}$');
