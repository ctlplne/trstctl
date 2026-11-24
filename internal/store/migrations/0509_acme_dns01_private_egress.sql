-- CR-062: retain the admission decision outside tenant-authored provider JSON.
-- Historical rows default to public-only access, even if their JSON contains
-- private network flags. Event replay also defaults to public-only.
ALTER TABLE acme_dns01_provider_configs
    ADD COLUMN allow_private_endpoint boolean NOT NULL DEFAULT false,
    ADD COLUMN private_egress_cidrs text[] NOT NULL DEFAULT '{}',
    ADD COLUMN private_egress_admission_version integer NOT NULL DEFAULT 0;
