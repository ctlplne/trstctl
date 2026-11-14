-- P1-L4: a delegated DNS-01 provider config can name where its
-- _validation-persist names point (their CNAME target), apart from the
-- _acme-challenge delegation target. Empty for every existing config, which
-- keeps publishing those names at the delegation target. Online-safe: adding
-- a column with a constant default rewrites no rows.
ALTER TABLE acme_dns01_provider_configs
    ADD COLUMN IF NOT EXISTS persist_delegation_target text NOT NULL DEFAULT '';
