-- A84: a github_oidc trust source may authenticate the workflow by itself.
--
-- Until now a GitHub Actions workflow needed an API token scoped to certs:issue
-- beside its OIDC attestation, so a long-lived trstctl secret lived in every
-- pipeline. A source flagged self_authenticating lets the verified OIDC token
-- be the bearer credential of POST /api/v1/workloads/attested-issuance for its
-- tenant; allowed_owners is the owner pin that keeps every other repository on
-- GitHub out, and the API refuses to flag a source without it. Existing sources
-- keep both defaults: nothing they were created with is reinterpreted.
ALTER TABLE workload_attester_trust_sources
    ADD COLUMN IF NOT EXISTS self_authenticating boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS allowed_owners text[] NOT NULL DEFAULT '{}'::text[];
COMMENT ON COLUMN workload_attester_trust_sources.self_authenticating IS
    'A84: the verified github_oidc token alone authenticates attested issuance for this tenant.';
COMMENT ON COLUMN workload_attester_trust_sources.allowed_owners IS
    'A84: lower-cased GitHub repository owners this source admits; required when self_authenticating.';
