# trstctl Demo Stack

Use this stack for a live solutions-engineering walkthrough. It brings up a local
OIDC provider, PostgreSQL, NATS JetStream, an isolated signer, LocalStack KMS, the
web/API server, and a seed job that creates realistic demo data through served
HTTPS APIs.

```bash
docker compose -f deploy/demo/docker-compose.yml up --build
```

Open <https://localhost:9443>, accept the local TLS certificate, and click **Sign
in with SSO**. The demo IdP signs you in as `demo-admin@trstctl.local` for tenant
`11111111-1111-4111-8111-111111111111`.

The seed job creates a 180-day realistic history: owners, members, profiles, an
internal CA catalog row, real signer-issued X.509 inventory, imported and
discovered certificates with different expiries, stored secrets, a dynamic PKI
secret, transit encryption/signing keys, LocalStack KMS-backed managed keys,
discovery jobs/runs, API tokens, ephemeral API keys, agent enrollment tokens,
audit-producing lifecycle transitions, and notification-facing preview rows.

To validate the demo plan without starting the stack:

```bash
node deploy/demo/seed.mjs --check
```

This stack is deliberately not the same command as the blank operational/eval
stack:

```bash
docker compose -f deploy/docker/docker-compose.yml up --build
```

Use `deploy/docker/docker-compose.yml` when you want an empty control plane wired
to explicit PostgreSQL/NATS services, closer to the path a corporate deployment
will harden. Use Helm with external managed datastores for production.

To stop the demo and keep its pre-populated data:

```bash
docker compose -f deploy/demo/docker-compose.yml down
```

To reset the demo to a fresh seed:

```bash
docker compose -f deploy/demo/docker-compose.yml down --volumes
docker compose -f deploy/demo/docker-compose.yml up --build
```
