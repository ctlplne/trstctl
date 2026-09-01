# trstctl Demo Stack

Use this stack for a live solutions-engineering walkthrough. It brings up a local
OIDC provider, PostgreSQL, NATS JetStream, an isolated signer, LocalStack KMS, the
web/API server, and a seed job that creates realistic demo data through served
HTTPS APIs.

```bash
docker compose -f deploy/demo/docker-compose.yml up --build
```

The UI and automatic demo IdP bind to host loopback, so the disposable demo
administrator is not exposed to the LAN. The IdP uses an exact callback allowlist,
PKCE, and short-lived single-use authorization codes. The stack creates one stable self-signed browser certificate and publishes only
its public half. Copy it out and verify the API before opening the browser:

```bash
docker compose -f deploy/demo/docker-compose.yml cp \
  trstctl:/public-trust/control-plane.crt ./trstctl-demo-control-plane.crt
curl --cacert ./trstctl-demo-control-plane.crt https://127.0.0.1:9443/healthz
```

Import `trstctl-demo-control-plane.crt` into the trust store used by your local
evaluation browser, then open <https://127.0.0.1:9443> and click **Sign in with
SSO**. Do not bypass a certificate warning: if the browser still warns, it is not
using the copied trust file. The demo IdP signs you in as
`demo-admin@trstctl.local` for tenant
`11111111-1111-4111-8111-111111111111`. Remove the local trust entry when the
evaluation ends.

Use that exact `127.0.0.1` browser URL. The blank stack uses `localhost`, and
the distinct loopback hostnames keep both host-scoped SSO cookies valid in one
browser profile even though the ports already differ.

The demo also publishes its mTLS agent channel at `localhost:29443` and its
current-certificate renewal listener at `localhost:29444`. Both are loopback-only.
The separate blank evaluation stack uses `19443` and `19444`, so its agents and the
demo agents can operate side by side without sharing a listener or trust boundary.

The real PostgreSQL-backed tenant rate limiter remains enabled. Its demo-only
burst is 10,000 requests per minute so the supported Chromium, Firefox, and
WebKit qualification matrix can exercise every live route without throttling
itself. This does not change the production default of 600 requests per minute;
operators should size that production boundary for their own tenant traffic.

The seed job creates a 180-day realistic history: owners, members, profiles, an
internal CA catalog row, real signer-issued X.509 inventory, imported and
discovered certificates with different expiries, stored secrets, a dynamic PKI
secret, transit encryption/signing keys, LocalStack KMS-backed managed keys,
discovery jobs/runs, API tokens, ephemeral API keys, agent enrollment tokens,
audit-producing lifecycle transitions, and notification-facing preview rows.

The seed is a convergent, versioned migration. It first reads each logical
resource, refuses duplicate or same-name/different-policy preserved data, and
advances lifecycle state only when that transition is still needed. Its final
event-sourced member is the durable `demo-seed-v2` completion checkpoint. A
valid v1 checkpoint is migrated in place; malformed or unknown checkpoint
versions still fail closed instead of guessing. The
bootstrap bearer needed to inspect preserved state lives in the non-public
`seedstate` volume as a mode-0600 file; it is never printed and is not part of
signer or KEK custody.

Re-running the same command with its volumes intact is safe. To wait for the
first seed and prove a second complete pass leaves logical inventory, immutable
event count, API-token count, and outbox count unchanged, run:

```bash
docker compose -f deploy/demo/docker-compose.yml wait demo-seed
scripts/ci/demo-seed-convergence.sh
```

The proof fails instead of choosing one row when preserved data already has a
duplicate logical owner or another conflicting demo resource. That is a data
repair signal, not permission for the seed to overwrite history.

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

`down --volumes` also removes the seed checkpoint and its persisted bootstrap
bearer, so the next `up` performs a genuinely fresh seed.

## Prove bootstrap custody across containers and restarts

The seed image is also the demo's reusable admin image. It does not start its own
signer or create a second credential-encryption key: `docker compose run` gives it
the running deployment's signer socket plus read-only views of the deployment KEK
and signer authorization secret. It receives only certificate material through a
separate public-trust volume; it cannot read the control plane's private data
volume. The authoritative issuing certificate remains at its historical
`/data/ca/issuing-ca.crt` path beside the preserved deployment state, and the
control plane publishes an exact certificate-only copy to public trust after it
successfully rebinds that certificate to the signer-held key. This keeps upgrades
stable without exposing `/data`. A separate admin service would only duplicate
that security-sensitive wiring.

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
