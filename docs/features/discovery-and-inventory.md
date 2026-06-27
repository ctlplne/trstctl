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
cryptography path. The served scanner also applies the shared SSRF guard and a
reserved-IP denylist before dialing expanded CIDRs, so a scan cannot be turned into a
loopback, RFC1918, link-local, or cloud-metadata probe.

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

The agent's discovery sources are `filesystem`, `pkcs11`, `windows-store`,
`k8s-secret`, `trust-store`, and `private-key`. The local read still runs inside the agent because
only the host can see its files, tokens, Windows store, trust stores, browser
profiles, or in-cluster Secrets. The report path is now served by the control plane:
an enrolled agent sends a metadata-only
`ReportInventory` batch over the same mTLS channel it uses for heartbeat and renewal,
and the server creates a tenant-scoped discovery source, run, findings, audit events,
and credential-graph nodes from that batch. The server rejects inline secret-looking
metadata keys, caps batch size, and runs ingest in the bounded agent lane, so a noisy
fleet cannot starve the API.

For Linux certificate files, the shipped agent can inventory public certificate roots
at startup with `--inventory-cert-roots`. It reports references, fingerprints, and
certificate metadata only — never private keys or secret values.

Trust-store discovery is a separate agent collector because a trusted CA is not the
same thing as a deployed service certificate. The agent can read public trust anchors
from OS trust directories, Java `cacerts`/JKS files, NSS profile exports, browser
profile exports, and Windows trust-store enumerators. Each finding is tagged with
`trust_store_kind` (`os`, `java`, `nss`, `browser`, or `windows`) and
`private_key_present=false`, so the control plane can answer "what does this host
trust?" without ever moving a key.

Private-key-material discovery is the companion collector for "what sensitive key
files exist here?" Operators point the agent at canary directories with
`--inventory-private-key-roots`. The agent reads each regular file locally, classifies
PKCS#8, PKCS#1 RSA, SEC1 EC, OpenSSH, and encrypted private-key containers through the
isolated cryptography boundary, wipes the file buffer after inspection, and reports
only the path, format, algorithm, file-mode metadata, and a fingerprint derived from
the public key when the key is parseable. Encrypted keys are still located and tagged
as encrypted, but no passphrase is requested and no private bytes, PEM blocks, or
secret values are sent to the control plane.

### SSH credential discovery (F42) — keys and standing access

SSH is where forgotten access hides. trstctl inventories SSH credentials two ways: a
network-side SSH handshake captures each host's **host key**, and the on-host agent
reads host keys, user keys, `authorized_keys` grants, `known_hosts` trust anchors, and
the `TrustedUserCAKeys` directive from `sshd_config`. DISC-03 extends the same agent
inventory path to private-key files, so SSH host/user key material and TLS key files
are located and classified as metadata-only `private_key` findings instead of being
copied into the control plane.

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

The control plane serves `cloud_certificate` discovery source/run/finding records and
executes AWS ACM, Azure Key Vault, and GCP Certificate Manager enumerators from the
outbox worker. Source configs use credential references such as
`access_key_id_ref`, `secret_access_key_ref`, and `token_ref`; inline cloud
credentials are rejected before a source is stored. LocalStack or emulator fixtures
can opt into a private endpoint, while normal provider endpoints use the public-URL
SSRF guard.

```json
{
  "kind": "cloud_certificate",
  "name": "aws-acm-east",
  "config": {
    "providers": [
      {
        "provider": "aws-acm",
        "region": "us-east-1",
        "access_key_id_ref": "env:AWS_ACCESS_KEY_ID",
        "secret_access_key_ref": "env:AWS_SECRET_ACCESS_KEY"
      }
    ]
  }
}
```

**Status:** source, schedule, run, provider execution, metadata-only findings, and
certificate-inventory projection are served.

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

Cloud secret-manager import extends that same metadata-only model to AWS Secrets
Manager and GCP Secret Manager for certificate material stored as secrets. The
providers read secret metadata and fingerprints, never secret values, and run under
the discovery bulkhead with the same tenant-scoped source/run/finding projection.

### Discovery triage

Findings are immutable evidence, but their operator triage state is mutable and
event-sourced. `triage_status` starts as `unmanaged`; the state model also includes
`investigating`, `managed`, and `dismissed`. The served API exposes
`POST /api/v1/discovery/findings/{id}/claim` to mark a finding managed, and
`POST /api/v1/discovery/findings/{id}/dismiss` to dismiss it with a reason. Both are
tenant-scoped, idempotent mutations guarded by `discovery:write`; the investigation
state remains a projected workflow state, not a separate public endpoint.

### In the console

The `/discovery` screen is the discovery front door: a **shadow-inventory** summary of
unmanaged credentials found across your environments, and a **CT-log & drift** panel that
counts certificate-transparency and configuration-drift findings — both projected over the
served sources, schedules, runs, and findings. See [The web console](../web-console.md).

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
`GET /api/v1/discovery/runs/{id}`, `GET /api/v1/discovery/findings`,
`POST /api/v1/discovery/findings/{id}/claim`, and
`POST /api/v1/discovery/findings/{id}/dismiss`.

To see enrolled agents that perform local discovery:

```sh
trstctl-cli agents list

# On an enrolled host, report public certificate files the agent can see.
trstctl-agent --enroll-url https://localhost:8443 \
  --bootstrap-token-file ./trstctl-bootstrap-token \
  --server localhost:9443 \
  --name edge-agent-1 \
  --ca-bundle ./trstctl-ca.pem \
  --inventory-cert-roots /etc/ssl,/etc/pki/tls/certs \
  --inventory-os-trust-roots /etc/ssl/certs,/etc/pki/ca-trust/source/anchors \
  --inventory-java-trust-stores "$JAVA_HOME/lib/security/cacerts" \
  --inventory-nss-trust-roots "$HOME/.pki/nssdb/exported-roots" \
  --inventory-browser-trust-roots "$HOME/.config/chromium/Default/exported-roots" \
  --inventory-private-key-roots /etc/ssl/private,/etc/ssh

# Then read the projected discovery inventory and graph from the control plane.
trstctl-cli discovery findings list
trstctl-cli graph nodes
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
| Agent-based discovery loop (F3) | **Served report path** — local filesystem, trust-store, private-key-material, token, Windows-store, and Kubernetes enumeration runs inside the agent; mTLS `ReportInventory` records source/run/finding rows and graph nodes |
| Network discovery (F2) | **Served** — source/schedule/run/finding APIs + CLI/UI; TLS scan executes through the outbox with reserved-IP SSRF filtering |
| Agentless cloud discovery (F49) | **Served** — source/schedule/run/finding records; AWS ACM, Azure Key Vault, and GCP Certificate Manager provider execution runs from the outbox with credential references |
| CT-log monitoring (F17) | **Partially served** — source/schedule/run/finding APIs + CLI/UI; CT polling executes through the outbox and raises notification alerts |
| Drift detection (F18) | **Partially served** — source/schedule/run/finding APIs + CLI/UI; watched-path fingerprint/mode checks execute through the outbox and raise notification alerts |
| SSH discovery (F42) | **Control-plane served** — source/schedule/run/finding records; host-key execution is agent/library-owned |
| Secret-store & API-key discovery (F35, F36) | **Control-plane served** — metadata-only references/fingerprints, never values; includes AWS Secrets Manager and GCP Secret Manager imports |

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
  `GET /api/v1/discovery/findings`, `POST /api/v1/discovery/findings/{id}/claim`,
  `POST /api/v1/discovery/findings/{id}/dismiss`, `GET /api/v1/agents`,
  `POST /api/v1/agents/enrollment-tokens`, `GET /api/v1/graph`,
  `POST /enroll/bootstrap`.
- **Agent channel:** `AgentService.ReportInventory` over the mTLS agent gRPC listener
  when `agent_channel.enabled` is true.
- **Config:** `TRSTCTL_LIFECYCLE_RENEW_BEFORE` (default `720h`) sets the
  expiry window the inventory and lifecycle treat as "renew soon".
- **Served discovery source kinds:** `network`, `cloud_certificate`, `ct_log`, `drift`,
  `manual`, plus metadata-only `ssh`, `secret_store`, `api_key`, and `agent`.
- **Discovery source kinds (agent):** `filesystem`, `pkcs11`, `windows-store`,
  `k8s-secret`, `trust-store`, `private-key`.
- **Agent inventory flags:** `--inventory-cert-roots`, `--inventory-os-trust-roots`,
  `--inventory-java-trust-stores`, `--inventory-java-trust-store-password`,
  `--inventory-nss-trust-roots`, `--inventory-browser-trust-roots`,
  `--inventory-private-key-roots`.
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
