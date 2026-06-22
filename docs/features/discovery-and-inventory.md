# Discovery & inventory — find every certificate, key, and secret you already have

## What it is

Before you can manage credentials, you have to *know they exist*. Discovery is how
trstctl finds the credentials already scattered across your infrastructure —
[certificates](../glossary.md), SSH keys, and [secrets](../glossary.md) — and the
**inventory** is the single, tenant-scoped list it keeps them in.

Think of it like a building's master key register. Before you can say "who can open
which door?", someone has to walk every floor, write down every lock and every key,
and keep that register current as locks change. trstctl is that walker and that
register, for machines.

trstctl discovers credentials five ways, and each suits a different corner of your
estate: scanning the network from outside, asking an agent what a host can see from
inside, pulling inventory straight from cloud provider APIs, reading SSH key files
and trust config, and connecting to external secret stores. Everything they find
lands in one inventory.

## Why it exists

Almost every organization has more machine credentials than it can name, and the ones
nobody remembers are the ones that cause outages and breaches: the certificate that
expires on a forgotten load balancer at 3 a.m., the SSH key a contractor left behind,
the API token hard-coded in a script five years ago. You cannot rotate, revoke, or
risk-score a credential you do not know about.

Discovery turns "we think we have a few hundred certs" into a precise, queryable
list — the foundation every other trstctl feature builds on. Risk scoring, drift
detection, the credential graph, and lifecycle automation all read the inventory.

## How it works

### The inventory (F1) — the source of truth that is actually a projection

The inventory is a PostgreSQL table of certificate **metadata** — subject, SANs,
issuer, serial, SHA-256 fingerprint, key algorithm, validity window, where it's
deployed, and lifecycle status. It never stores a private key.

Here's the important part, and it's a core trstctl design rule
([event sourcing](../glossary.md)): nothing writes to that table directly. When a
certificate is discovered or issued, the orchestrator appends a `certificate.recorded`
event to the append-only, tamper-evident log, and a *projector* reads that event and
builds the table row. The table is a **projection** — a derived view you could delete and
rebuild from the log. That's why trstctl can survive a database loss: the truth is the
event log, and the inventory is just a fast index into it.

Ingestion is idempotent: the row key is `(tenant_id, fingerprint)`, so seeing the same
certificate twice refreshes one row instead of creating a duplicate, and the ingest API
requires an [`Idempotency-Key`](../glossary.md) so a retried request can't double-record.
Certificate parsing routes through the single isolated cryptography path, so the inventory
code itself never touches the low-level X.509 libraries directly.

### Network discovery (F2) — scanning from the outside, no agent needed

Network discovery connects to IP/port ranges you define, performs a normal
[TLS](../glossary.md) handshake, captures the certificate each host presents, and
records its metadata. No software is installed on the targets — it sees exactly what
any client on the network would see.

The scanner runs in its own bounded [lane](../glossary.md): a bounded pool of workers
(default 16, queue 256). When the queue fills, it slows the producer instead of dropping
targets or exhausting the pool the API needs — a big scan can never starve the rest of the
system. The handshake and certificate parsing both go through the single isolated
cryptography path.

**Status:** served by the running control plane: operators create a `network` source,
queue a run, and inspect findings through REST/CLI/UI. The run executes from the outbox
worker — the external probes are journaled first and delivered at-least-once, so they're
durable and retryable instead of being done inline by the request handler.

### Agent-based discovery (F3) — what each host can see from the inside

A network scan only sees what a host *presents on a port*. Plenty of credentials never
appear on the wire: a certificate sitting in a file, in a PKCS#11 token, in the
Windows certificate store, or in a Kubernetes Secret. The trstctl **agent** runs on
the host and enumerates those local sources, then reconciles what it finds into the
inventory over its mutually-authenticated ([mTLS](../glossary.md)) channel.

Each source is independent: if one token errors, the agent records the error and keeps
going, so one broken source can't hide the rest. The agent enrolls into the control
plane with a one-time bootstrap token (`POST /enroll/bootstrap`), after which the
control plane lists it at `GET /api/v1/agents`.

The agent's discovery sources are `filesystem`, `pkcs11`, `windows-store`, and
`k8s-secret`. The discovery loop runs inside the agent binary; agent *enrollment* is
served by the control plane.

### SSH credential discovery (F42) — keys and standing access

SSH is where forgotten access hides. trstctl inventories SSH credentials two ways: a
network-side SSH handshake captures each host's **host key**, and the on-host agent
reads host keys, user keys, `authorized_keys` grants, `known_hosts` trust anchors, and
the `TrustedUserCAKeys` directive from `sshd_config`.

Two flags make the result actionable. **StandingAccess** marks an entry that grants
persistent login (an `authorized_keys` line). **Orphaned** marks a standing-access
grant whose comment field is blank — meaning nobody can say whose key it is. An
orphaned standing-access key is exactly the thing a security team wants surfaced. Only
the fingerprint is ever stored, never private key material (held in wipeable memory and
zeroed after use, never written down).

The control plane serves `ssh` discovery source/run/finding records. **Status:** SSH
source, schedule, run, and metadata-only finding records are served; host-key execution
still belongs to the agent/library connector.

### Agentless cloud discovery (F49) — pull inventory from the cloud's own APIs

Cloud platforms already keep a list of your certificates; you just have to ask.
trstctl's cloud enumerators call the provider control planes read-only — **AWS** ACM,
**Azure** Key Vault, and **GCP** Certificate Manager — page through the results, and
record the metadata. No agent, no network reachability required, just read-only cloud
credentials. Request signing (e.g. AWS SigV4) and all certificate parsing go through the
single isolated cryptography path, and the enumerators run in their own bounded lane with
retry/backoff on rate limits — overload is rejected fast instead of starving other work.

The control plane serves `cloud_certificate` discovery source/run/finding records.
**Status:** cloud source, schedule, run, and metadata-only finding records are served;
provider API execution remains connector-owned and uses credential references rather than
inline credentials.

### Secret-store & API-key discovery (F35, F36) — names, never values

Secrets and API keys live in many systems, and the dangerous ones are the stale,
never-rotated, high-privilege ones. trstctl's discovery connectors enumerate them by
**reference only** — path, name, ARN, metadata — and *never read the value* (the data type
literally has no value field, so a value can't leak into the inventory). Sources include
HashiCorp Vault, AWS
Secrets Manager / IAM access keys, Azure Key Vault / service-principal secrets, GCP
Secret Manager / service-account keys, Kubernetes Secrets, GitHub Actions secrets,
and Infisical.

Each finding becomes a node in the [credential graph](graph-query-ai.md) with its
**provenance** (where it came from) and a **risk score** — API keys start at 60,
tokens at 50, stored secrets at 30, with +30 for stale or never-rotated — and a
`discovery.found` audit event is recorded in the tamper-evident log. A related bridge
ingests leaked-credential findings from scanners (gitleaks, trufflehog) into the same
graph, again structurally excluding the secret value.

The control plane serves `secret_store` and `api_key` discovery source/run/finding
records. **Status:** source, schedule, run, and metadata-only finding records are served.
Connector execution records references and fingerprints, not secret values.

## Use it

The certificate inventory (F1) is live today. Drive it from the CLI:

```sh
# list certificates, newest first, paginated
trstctl-cli certificates list --limit 50

# list only certificates expiring within a window
trstctl-cli certificates list --expiring-before 720h

# ingest a certificate you already have (idempotent)
trstctl-cli certificates ingest -f ./server.pem
```

Those map to the served REST routes `GET /api/v1/certificates` and
`POST /api/v1/certificates` (the latter requires an `Idempotency-Key` header).

Network discovery is live too:

```sh
cat > source.json <<'JSON'
{"kind":"network","name":"edge","config":{"targets":["10.0.0.10:443"]}}
JSON
trstctl-cli discovery sources create -f source.json
trstctl-cli discovery sources list

cat > run.json <<'JSON'
{"source_id":"<source-id>"}
JSON
trstctl-cli discovery runs start -f run.json
trstctl-cli discovery runs list
trstctl-cli discovery findings list --run_id <run-id>
```

Those map to `POST|GET /api/v1/discovery/sources`,
`POST|GET /api/v1/discovery/schedules`, `POST|GET /api/v1/discovery/runs`,
`GET /api/v1/discovery/runs/{id}`, and `GET /api/v1/discovery/findings`.

To see enrolled agents that perform local discovery:

```sh
trstctl-cli agents list
```

When you find a credential you didn't expect, follow it into the
[credential graph](graph-query-ai.md) to see what it can reach, or into
[risk scoring](observability-and-risk.md) to see why it matters.

## Pitfalls & limits

Be precise about what runs in the server today versus what ships as tested library
code awaiting control-plane wiring (this matters for an honest evaluation — see also
[Current limitations](../limitations.md)):

| Capability | Status today |
|---|---|
| Certificate inventory (F1) | **Served** — REST + CLI, event-sourced |
| Agent enrollment (for F3) | **Served** — `/enroll/bootstrap`, `/api/v1/agents` |
| Agent-based discovery loop (F3) | Runs **inside the agent binary** |
| Network discovery (F2) | **Served** — source/schedule/run/finding APIs + CLI/UI; TLS scan executes through the outbox |
| Agentless cloud discovery (F49) | **Control-plane served** — source/schedule/run/finding records; provider execution is connector-owned |
| SSH discovery (F42) | **Control-plane served** — source/schedule/run/finding records; host-key execution is agent/library-owned |
| Secret-store & API-key discovery (F35, F36) | **Control-plane served** — metadata-only references/fingerprints, never values |

Other gotchas: a network scan only sees what a host presents on a port at scan time —
pair it with agent-based discovery for the full picture. Cloud discovery needs
read-only credentials with list/get permission on the relevant service. Secret-store
discovery records *references*, so a finding tells you a secret exists and where, not
what it is.

## Reference

- **CLI groups:** `certificates`, `discovery`, `agents` (full set: `owners`,
  `issuers`, `identities`, `certificates`, `discovery`, `profiles`, `audit`,
  `graph`, `risk`, `agents`).
- **Served routes:** `GET|POST /api/v1/certificates`, `GET /api/v1/certificates/{id}`,
  `GET|POST /api/v1/discovery/sources`, `GET|POST /api/v1/discovery/schedules`,
  `GET|POST /api/v1/discovery/runs`, `GET /api/v1/discovery/runs/{id}`,
  `GET /api/v1/discovery/findings`, `GET /api/v1/agents`,
  `POST /api/v1/agents/enrollment-tokens`, `POST /enroll/bootstrap`.
- **Config:** `TRSTCTL_LIFECYCLE_RENEW_BEFORE` (default `720h`) sets the
  expiry window the inventory and lifecycle treat as "renew soon".
- **Discovery source kinds (agent):** `filesystem`, `pkcs11`, `windows-store`,
  `k8s-secret`.
- **Audit events:** `certificate.recorded`, `discovery.source.upserted`,
  `discovery.schedule.upserted`, `discovery.run.queued`, `discovery.run.started`,
  `discovery.finding.recorded`, `discovery.run.completed`, `secretscan.finding`.

## See also

[Observability & risk](observability-and-risk.md) (scoring what you discover) ·
[Graph, query & AI](graph-query-ai.md) (what a credential can reach) ·
[Secrets](secrets.md) · [Current limitations](../limitations.md) ·
glossary: [certificate](../glossary.md), [fingerprint](../glossary.md),
[bulkhead](../glossary.md), [event sourcing](../glossary.md)

**Covers:** F1, F2, F3, F42, F49, F35, F36
