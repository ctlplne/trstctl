-- Agent capability grants on the bootstrap token (epic A2).
--
-- An agent can run in one of two places. On the host, where it deploys and
-- verifies credentials for the machine it lives on. Or in the network segment,
-- relaying for things that cannot host an agent at all — load balancers,
-- appliances, cloud certificate stores — which means holding the credentials that
-- drive them.
--
-- Which of those an agent is has to be decided by the operator who enrolled it,
-- not by a flag the agent passes at startup. A startup flag is something the
-- agent chooses; a certificate is something an operator granted. The distinction
-- is the whole control: an agent that could name itself a relay could name itself
-- into an appliance credential lease.
--
-- So the grant is recorded here, at mint, and travels: the redeeming CA stamps it
-- into the issued certificate as an additive role SAN, and the served channel
-- reads capability off that certificate rather than off anything the agent says
-- about itself at call time.
--
-- Empty is host-only, and that is deliberate rather than incidental. Every agent
-- enrolled before this migration has no grant recorded and no role SAN in its
-- certificate, and every one of them was doing host work. Reading "no roles" as
-- "no capability" would strand a live fleet mid-upgrade; reading it as host-only
-- describes what those agents already are.
--
-- online-safe: ADD COLUMN with a constant default is a catalog-only change in
-- PostgreSQL 11+ (no table rewrite, no full-table lock held while data is
-- copied). The table is small and short-lived besides — bootstrap tokens expire
-- within the hour.
ALTER TABLE agent_bootstrap_tokens
    ADD COLUMN IF NOT EXISTS granted_roles text[] NOT NULL DEFAULT '{}';

-- The set of grantable roles is closed, and the database is where that closure is
-- actually enforced. Application code normalizes and rejects unknown roles too,
-- but a constraint here means no path — a migration, a repair script, an operator
-- with psql — can leave a row carrying a capability the certificate stamper has
-- no meaning for.
ALTER TABLE agent_bootstrap_tokens
    ADD CONSTRAINT agent_bootstrap_tokens_roles_known
    CHECK (granted_roles <@ ARRAY['host', 'network']::text[]);

COMMENT ON COLUMN agent_bootstrap_tokens.granted_roles IS
    'Capability grant stamped into the enrolled certificate as role SANs (epic A2). Empty = host-only.';
