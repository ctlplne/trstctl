# CLI

`trstctl-cli` is a command-line interface at parity with the REST API, built for
scripts and CI: machine-readable JSON output and a CI-friendly API token. The
command set is generated from the API route table, so it stays in lockstep with
the server.

The running control plane also publishes its full **OpenAPI 3.1** specification at
`/api/v1/openapi.json` — fetch it to generate clients or import the API into your
tooling.

Prefer a typed library? trstctl ships supported **client SDKs for Go and
TypeScript** (with auth, `Idempotency-Key`, cursor iterators, problem+json
errors, and retries) pinned to that same served contract. See
[Client SDKs](features/client-sdks.md).

## Global flags

Every command accepts these, each with a `TRSTCTL_*` environment fallback:

| Flag | Env | Meaning |
| --- | --- | --- |
| `--server` | `TRSTCTL_SERVER` | Base URL of the control plane. |
| `--token` | `TRSTCTL_TOKEN` | API token, sent as `Authorization: Bearer`. |
| `--tenant` | `TRSTCTL_TENANT` | Tenant id (`X-Tenant-ID`) for header/dev auth. |
| `--idempotency-key` | `TRSTCTL_IDEMPOTENCY_KEY` | Stable key for safe retries; generated per call if unset. |

A trstctl API token carries its own tenant and scopes, so with `--token` you
usually need nothing else. Mutations always send an `Idempotency-Key` so a
retried command can never execute twice.

## Output and exit codes

Responses are pretty-printed JSON on stdout. Exit code is **0** on success, **1**
on a request/response error (the status is written to stderr), and **2** on a
usage error — scriptable end to end.

## Commands

One command per core API operation:

| Group | Commands |
| --- | --- |
| `owners` | `create` · `list` · `get` · `update` · `delete` |
| `issuers` | `create` · `list` · `get` |
| `identities` | `create` · `list` · `get` · `transition` |
| `certificates` | `ingest` · `list` · `get` |
| `profiles` | `create` · `list` · `get-version` |
| `audit` | `events` · `export` |
| `privacy` | `erasures erase` · `erasures list` · `retention run` · `retention list` · `catalog` |
| `graph` | `nodes` · `reachable` · `blast-radius` · `query` |
| `risk` | `credentials` |
| `agents` | `list` · `enroll-token` |

Plus `version`.

## Bootstrapping the first API token

`trstctl-cli` authenticates with an API token, but a freshly deployed control
plane has none and fails closed (every route `401`s). Mint the first one with the
**server** binary's first-run bootstrap verb, run on the control-plane host — it
writes straight to the datastore (no existing credential, no network trust
required) and prints a tenant-scoped token once:

```bash
trstctl token create --tenant <uuid> [--subject <name>] [--scopes a,b,c] [--tenant-name <label>]
```

- `--tenant` (required) is the UUID the token is scoped to; the tenant is
  registered through the event log if it does not exist yet.
- The default scope set is full operator control **excluding** certificate
  issuance (`certs:issue`) — bootstrapping a credential never grants self-issue.
- The raw `trst_…` token is printed once to stdout (only its hash is stored); save
  it immediately. Then export it as `TRSTCTL_TOKEN` for `trstctl-cli`.

## Examples

```bash
export TRSTCTL_SERVER=https://localhost:8443
export TRSTCTL_TOKEN=trst_...

# Create an owner from a JSON body on stdin.
echo '{"kind":"workload","name":"payments"}' | trstctl-cli owners create -f -

# List the certificate inventory.
trstctl-cli certificates list --limit 50

# Rank credentials by risk — what to rotate first.
trstctl-cli risk credentials --sort score

# Mint a one-time agent bootstrap token, then list registered agents.
trstctl-cli agents enroll-token
trstctl-cli agents list

# Run a graph query.
trstctl-cli graph query "MATCH (c:Certificate)-[:SIGNED_BY]->(i:Issuer) RETURN c,i"
```

Path parameters are positional; list filters (`--limit`, `--cursor`, `--sort`,
…) are flags; request bodies come from `-f <file>` or `-f -` (stdin).
