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

This also preserves the isolated signer's `agent-ca` key and its public trust
anchor at `/data/ca/agent-ca.crt`. Ordinary image rebuilds and container
recreation reuse the exact key and certificate; do not remove only one of those
volumes/files.

To reset the demo to a fresh seed:

```bash
docker compose -f deploy/demo/docker-compose.yml down --volumes
docker compose -f deploy/demo/docker-compose.yml up --build
```

## Prove bootstrap custody across containers and restarts

The seed image is also the demo's reusable admin image. It does not start its own
signer or create a second credential-encryption key: `docker compose run` gives it
the running deployment's signer socket plus read-only views of the deployment KEK,
signer authorization secret, and audit data. A separate admin service would only
duplicate that security-sensitive wiring.

Run the assembled custody proof from the repository root:

```bash
bash deploy/demo/aud68-custody-proof.sh
```

Prerequisites are Bash, `curl`, `jq`, `cmp`, a locally reachable Docker Engine, and
Docker Compose v2 with `wait`, `up --wait`, and `--wait-timeout`. Host ports 9443
and 19081 must be free for the disposable stack. The script checks the commands,
Compose features, daemon, and Docker-name collisions before it builds anything.

The script derives a genuinely unique Compose project from an exclusively created
temporary directory. Its cleanup trap can run `down --volumes` only for that exact,
validated project name, so it never addresses the normal `trstctl-demo` project or
its containers and volumes. The proof also overrides the ordinary demo's local
image tags with two project-unique tags, refuses exact container/network/volume/image
name collisions even when an object lacks Compose labels, and removes only those
proof-owned image tags after its containers are down.

The seed, running control image, and a distinct admin container all replay the same
fixed tenant-registration receipt. Narrow tokens are kept only in mode-0600 files;
the proof rejects any token file containing bytes beyond the one minted token, and
token values are neither printed nor placed in process arguments. Both control and
admin tokens authenticate a tenant-local certificate read before and after the
control/signer restart. Each read must return at least one seeded certificate whose
identifier, tenant, subject, fingerprint, and status match the served schema. With
normal appenders stopped, wrong and missing custody runs must fail with empty stdout
while exact PostgreSQL tenant/token/registration authority and JetStream event-head
snapshots remain unchanged.
