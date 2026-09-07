# Configuration

trstctl resolves its configuration from, in increasing precedence: built-in
defaults, an optional JSON config file (`TRSTCTL_CONFIG_FILE`), and environment
variables. The configuration is validated on boot — a bad combination **fails
fast** rather than starting half-configured.

Inspect the effective configuration at any time (credentials are redacted):

```bash
trstctl -check-config
```

## Server

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_SERVER_ADDR` | `:8443` | Address the control plane listens on. |
| `TRSTCTL_SERVER_TLS_MODE` | `internal` | `internal` (self-signed), `file` (operator cert), or `disabled` (plaintext, dev only). |
| `TRSTCTL_SERVER_TLS_CERT_FILE` | — | Server certificate chain (PEM); **required** when `mode=file`. |
| `TRSTCTL_SERVER_TLS_KEY_FILE` | — | Server private key (PEM); **required** when `mode=file`. |
| `TRSTCTL_SERVER_TLS_INTERNAL_STATE_FILE` | `data/tls/internal-server.pem` | Mode-`0600` combined certificate/private-key state used only by `mode=internal`. Keep it on persistent private storage so an inspected evaluation trust pin survives restart. Never distribute this file; capture only the public certificate from the TLS endpoint. |
| `TRSTCTL_SERVER_TLS_INTERNAL_TRUST_FILE` | `data/tls/internal-server.crt` | Certificate-only PEM published by `mode=internal`. Give this file to evaluation clients that must verify the self-signed server. It contains no private key and must never point at the private state file above. |
| `TRSTCTL_SERVER_TLS_MIN_VERSION` | `1.3` | Lowest TLS version the served listener negotiates. `1.3` is the default and the only floor for a credential control plane; `1.2` is an explicit opt-in for device-enrollment fleets whose stock EST/SCEP/CMP clients cap at TLS 1.2 (cisco libest does), and offers AEAD suites only. |
| `TRSTCTL_DEV_ALLOW_PLAINTEXT` | `false` | Explicit local-dev override required when `TRSTCTL_SERVER_TLS_MODE=disabled`; `TRSTCTL_SERVER_ADDR` must also bind loopback only. |
| `TRSTCTL_CORS_ALLOWED_ORIGINS` | empty (same-origin only) | Comma-separated exact browser Origins (scheme+host+port, e.g. `https://console.example.com`) allowed to make cross-origin, credentialed requests to the API (SEC-003). Empty means same-origin only: no `Access-Control-Allow-Origin` is emitted, so a cross-origin XHR is blocked by the browser. `*` is deliberately not honored for a credentialed API. |
| `TRSTCTL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |
| `TRSTCTL_LOG_FORMAT` | `json` | `json` or `text`. |

### Transport encryption (TLS)

The control plane serves over **TLS by default** so no credential, token, or
session ever travels in cleartext.

- **`internal`** (default) — the control plane creates a self-signed certificate
  once and reloads it from `server.tls.internal_state_file` on later starts. The
  certificate covers `localhost`, `127.0.0.1`, the first-boot hostname, and the
  Compose service name `trstctl`. Existing malformed, expired, or group/world-
  readable state fails closed instead of rotating trust silently. The server
  atomically publishes the matching certificate-only PEM at
  `server.tls.internal_trust_file`; clients verify with that file instead of
  disabling TLS checks. This is suitable for evaluation and tightly controlled internal or
  air-gapped use. Public deployments must use `server.tls.mode=file` with an
  operator-provided certificate chain from your CA; do not expose the eval
  self-signed certificate to public clients.
- **`file`** — the control plane presents an operator-provided certificate and
  key. Use this in production with a certificate from your CA. A missing or
  malformed file fails fast at startup rather than falling back to plaintext.
- **`disabled`** — plaintext HTTP. **Local development only** and mechanically
  bounded: startup fails unless `TRSTCTL_DEV_ALLOW_PLAINTEXT=true` and
  `TRSTCTL_SERVER_ADDR` is loopback-only (`localhost`, `127.0.0.1`, or `::1`).
  Production TLS termination should use `server.tls.mode=file` at trstctl or a
  TLS-terminating proxy in front of a TLS-enabled trstctl listener; disabled mode
  is not the production proxy pattern.

The control-plane↔signer channel (the private keys live in a separate, isolated
process) is independent of this setting. The
**default** (single-binary `child` mode, and `external` mode with `signer.socket`)
is a **peer-authenticated Unix domain socket** — a `0600` socket in a `0700`
directory, restricted to the signer's own uid via `SO_PEERCRED` on Linux — not a
TLS channel. For a **separately-hosted signer across nodes**, set
`signer.mtls_address` (with the `signer.mtls_*` certificate material): the control
plane then reaches the signer over **mTLS** — TLS 1.3, AEAD-only, with the control
plane and the signer each **pinning** the other's certificate (an untrusted or
merely CA-signed-but-unpinned peer is rejected, fail-closed). Exactly one of
`signer.socket` or `signer.mtls_address` is used in `external` mode; a partial mTLS
block fails closed at startup.

## Datastores

trstctl stores its read state in **PostgreSQL** (the source-of-truth event log
lives in **NATS JetStream**). PostgreSQL is the datastore in every deployment mode
— there is no SQLite path.

!!! important "Datastores: bundled single-node for eval, external for production"
    The serving binary (`trstctl`, via `server.Run`) can run a single-node eval
    stack: bundled PostgreSQL (`TRSTCTL_POSTGRES_MODE=bundled`, the default — the
    binary starts and supervises an embedded single-node Postgres with data under
    `TRSTCTL_POSTGRES_DATA_DIR` on `TRSTCTL_POSTGRES_PORT`, default 5432) and
    embedded NATS (`TRSTCTL_NATS_MODE=embedded`, the default — in-process
    file-backed JetStream). Bundled PostgreSQL is available only for host archives
    with committed runtime pins in `deploy/supply-chain/embedded-postgres.json`
    (summarized in [Supply chain](supply-chain.md)):
    currently `linux-amd64`, `linux-arm64v8`, and `darwin-arm64v8`. It downloads
    that pinned PostgreSQL runtime once on first use, verifies the cached archive
    before execution, and fails closed if the host archive is unsupported, unpinned,
    or hash-mismatched. For **production**, use `external` for both:
    `TRSTCTL_POSTGRES_MODE=external` with `TRSTCTL_POSTGRES_DSN` and
    `TRSTCTL_NATS_MODE=external` with `TRSTCTL_NATS_URL`, which the Compose stack
    and Helm chart wire up. There is **no silently-failing default**: an invalid
    mode — or `external` without a DSN — fails fast at startup. (External mode
    never downloads anything. `--migrate` / `--backup` target a managed datastore
    and require `external`.)

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_POSTGRES_MODE` | `bundled` | `bundled` (embedded single-node eval on a manifest-pinned host archive; downloads once and fails closed if unpinned) or `external` (managed cluster; recommended for production). |
| `TRSTCTL_POSTGRES_DSN` | — | Connection string; **required** when mode is `external`. |
| `TRSTCTL_POSTGRES_DATA_DIR` | `data/postgres` | Data directory for the **bundled** datastore; eval data persists here across restarts. |
| `TRSTCTL_POSTGRES_PORT` | `5432` | Loopback port for the **bundled** datastore (override if 5432 is taken). |
| `TRSTCTL_POSTGRES_STATEMENT_TIMEOUT` | `60s` | Server-side deadline applied to every statement (OPS-TIMEOUTS-001), so a stuck query fails closed instead of holding a connection indefinitely. DR rebuild/restore transactions widen this explicitly. |
| `TRSTCTL_POSTGRES_ACQUIRE_TIMEOUT` | `10s` | How long a request may wait for a pooled PostgreSQL connection before failing closed with a structured `503`. |
| `TRSTCTL_NATS_MODE` | `embedded` | `embedded` (in-process file-backed JetStream for single-node eval) or `external` (NATS cluster; recommended for production). |
| `TRSTCTL_NATS_URL` | — | NATS URL; **required** when external (i.e. to serve). |
| `TRSTCTL_NATS_STORE_DIR` | `data/nats` | JetStream store directory for the embedded datastore. |
| `TRSTCTL_NATS_REPLICAS` | `3` in external, `1` embedded | Required JetStream replicas for the source-of-truth event stream. External startup/readiness fail if NATS cannot honor the requested count. |
| `TRSTCTL_NATS_ALLOW_SINGLE_REPLICA` | `false` | Eval-only opt-in that permits `TRSTCTL_NATS_REPLICAS=1` in external mode. Do not enable it for production HA/RPO. |
| `TRSTCTL_NATS_SYNC_INTERVAL` | `1s` | How often the **embedded** JetStream fsyncs the stream to stable storage (RESIL-001). nats-server's own default is ~2 minutes; trstctl tightens it so a single-node power loss loses at most ~1s of acked events. Only affects embedded mode; an external cluster manages its own durability. |
| `TRSTCTL_NATS_SYNC_ALWAYS` | `false` | Fsyncs the **embedded** JetStream on every append (`O_SYNC`) instead of on the interval, for a near-zero single-node RPO at a throughput cost. Only affects embedded mode. |

### External datastores

To point trstctl at managed PostgreSQL and NATS, switch both to external mode and
supply their connection strings:

```bash
export TRSTCTL_POSTGRES_MODE=external
export TRSTCTL_POSTGRES_DSN='postgres://user:pass@db.internal:5432/trstctl?sslmode=require'
export TRSTCTL_NATS_MODE=external
export TRSTCTL_NATS_URL='nats://nats.internal:4222'
export TRSTCTL_NATS_REPLICAS=3
```

When a mode is `external`, its connection string is mandatory; trstctl refuses to
start without it. External NATS also refuses to serve under-replicated: the event
stream defaults to three replicas, startup fails on a non-clustered single NATS
server, and `/readyz` reports degraded if the observed stream later has fewer
replicas than configured. The Docker Compose eval stack uses the same external code
path but explicitly sets `TRSTCTL_NATS_REPLICAS=1` and
`TRSTCTL_NATS_ALLOW_SINGLE_REPLICA=true`; keep that opt-in out of production.

### Schema migrations

trstctl embeds its PostgreSQL schema as versioned SQL migrations and applies them
itself; there is no separate migration binary.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_MIGRATE_AUTO` | `true` | Applies pending schema migrations automatically on startup, serialized across replicas by the same PostgreSQL advisory lock leader election uses. Set `false` for a production posture where migrations are an explicit, backed-up step: a control plane that finds pending migrations then fails fast with guidance instead of changing the schema. |

`trstctl --migrate` applies pending migrations under the advisory lock and exits;
`trstctl --migrate-status` lists the pending plan (dry run) and exits. See
[Database migrations & upgrades](migrations.md) for the full upgrade/rollback runbook.

### High availability (leader election and snapshots)

trstctl is safe to run as more than one control-plane replica against one shared
external PostgreSQL and NATS (RESIL-002 / RESIL-004). With the defaults, a single
replica behaves exactly as before; adding replicas needs no extra configuration
beyond pointing them at the same datastores.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_HA_LEADER_ELECTION` | `true` (unset defaults on) | Gates the continuous background workers — the projector tailer, outbox dispatcher, GC sweeps, CRL scheduler, audit-retention worker, and snapshot worker — behind a PostgreSQL session-scoped advisory lock so exactly one replica runs them; every replica still serves reads. Leave it on for any multi-replica deployment: turning it off with more than one replica reintroduces double-projection. The leader frees the lock automatically on crash, so a follower fails over with no lease tuning. |
| `TRSTCTL_HA_LEADER_CAMPAIGN_INTERVAL` | `3s` | How often a follower retries to acquire leadership, and how often the leader re-checks it still holds the lock. Shorter gives faster failover at the cost of more try-lock probes. |
| `TRSTCTL_HA_SNAPSHOT_INTERVAL` | `5m` | How often the leader persists a read-model snapshot at the current projection checkpoint (SPINE-007), so a later cold boot / DR restore replays only the tail instead of the full event log. Set `0` to disable periodic snapshots (boot then does a full checkpoint catch-up; the log stays the source of truth). |

### Cross-cluster federation

Federation is disabled by default. When enabled on a passive cluster, the leader
worker imports a peer's event log into the local event log, advances a durable peer
cursor, and projects the imported events locally. The passive region therefore serves
from its own PostgreSQL and NATS after failover; it does not read the primary region's
PostgreSQL tables.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_FEDERATION_ENABLED` | `false` | Enable the leader-only peer import worker. |
| `TRSTCTL_FEDERATION_CLUSTER_ID` | — | Stable id for this cluster, for example `us-west-passive`; required when enabled. |
| `TRSTCTL_FEDERATION_REGION` | — | Human/operator region label for this cluster. |
| `TRSTCTL_FEDERATION_PEER_ID` | — | Stable id of the source cluster; required for env-configured single-peer federation. |
| `TRSTCTL_FEDERATION_PEER_REGION` | — | Human/operator region label for the source cluster. |
| `TRSTCTL_FEDERATION_PEER_NATS_URL` | — | Source cluster NATS URL. The source must expose its trstctl event stream over external NATS. |
| `TRSTCTL_FEDERATION_INTERVAL` | `1s` | How often the passive cluster polls the peer log. This is the main operator-tuned RPO knob. |
| `TRSTCTL_FEDERATION_RPO` | `5s` | Operator target for maximum accepted replication lag. Use this in runbooks and monitoring. |
| `TRSTCTL_FEDERATION_RTO` | `30s` | Operator target for passive-region promotion after traffic moves. |

JSON config can declare multiple peers under `federation.peers`; the environment
overlay above configures one common peer. Keep `ha.leader_election` on so one replica
owns imports while all replicas serve the replicated read state.

## Lifecycle

How far ahead of expiry trstctl renews and alerts. Values are Go durations.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_LIFECYCLE_RENEW_BEFORE` | `720h` (30 days) | Renew this far before expiry. |
| `TRSTCTL_LIFECYCLE_ALERT_BEFORE` | `336h` (14 days) | Alert this far before expiry. |
| `TRSTCTL_LIFECYCLE_LEAF_VALIDITY` | `2160h` (90 days) | Reference leaf lifetime the **CA calendar** measures each authority's remaining horizon against, so the scheduler can say "this authority can no longer issue a full-length leaf" and the console can show a renew/re-key-by date. A yardstick for horizon reporting only — it caps nothing. |
| `TRSTCTL_LIFECYCLE_OWNERSHIP_ATTESTATION_CADENCE` | `2160h` (90 days) | How long an authenticated owner decision authorizes a steady-state deployment. Values must be from `1h` through `8760h`. At expiry, deployment fails closed unless the identity has an active attributed exception, and the bounded lifecycle scheduler emits one re-attestation request plus one outbox notification for the stale verification edge. |

## Native connector and external-CA assembly

The 24 native deployment connectors and 14 external-CA drivers are compiled into
`trstctl`, but start deny-by-default: the operator chooses the exact integrations to
construct. The connector allowlist and its shared network policy — which native
connectors may be constructed, the shared HTTP timeout, private-CIDR grants, and the
loopback-only insecure-HTTP escape hatch — are flattened into the environment
variables below.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_CONNECTORS_ENABLED` | unset (none) | Comma-separated allowlist of native connector names to construct, drawn from the closed set compiled into the binary (`nginx`, `apache`, `caddy`, `envoy`, `iis`, `haproxy`, `f5`, `netscaler`, `a10`, `kemp`, `cisco`, `fortigate`, `paloalto`, `postfix`, `traefik`, `aws-acm`, `azure-keyvault`, `gcp-certificate-manager`, `java-keystore`, `postgresql`, `mysql`, `rabbitmq`, `elasticsearch`, `tomcat`). Names left out of the list construct no target. |
| `TRSTCTL_CONNECTORS_HTTP_TIMEOUT` | `15s` | HTTP timeout applied to connector calls, for example the `right_size` PATCH/GET cycle. Must be a positive Go duration. |
| `TRSTCTL_CONNECTORS_ALLOW_PRIVATE_CIDRS` | unset | Comma-separated CIDRs explicitly granted to connector HTTP endpoints that resolve to a private address. |
| `TRSTCTL_CONNECTORS_ALLOW_INSECURE_HTTP` | `false` | Loopback-only development escape hatch permitting an `http://` connector endpoint (for example a local `right_size` emulator); it cannot authorize plaintext to a non-loopback host. |

The **tenant-bound structured bindings** — `connectors.local_profiles` (local
execution profiles), `connectors.right_size` (tenant-to-endpoint bindings), and every
`external_cas` entry — remain JSON/YAML config-file only, because they carry
tenant/provider associations where a parallel-list typo could cross a security
boundary.

A local connector needs both an enabled driver and an operator-owned execution
profile. Tenant target JSON can then select that profile, but cannot invent a command
or escape its allowed roots:

```json
{
  "connectors": {
    "enabled": ["nginx", "f5"],
    "http_timeout": "15s",
    "allow_private_cidrs": ["10.40.0.0/16"],
    "local_profiles": {
      "nginx-prod": {
        "allowed_roots": ["/etc/nginx/tls"],
        "actions": [{
          "logical_name": "nginx",
          "command": "/usr/sbin/nginx",
          "pass_args": true,
          "timeout": "15s"
        }]
      }
    },
    "right_size": [{
      "tenant_id": "11111111-1111-4111-8111-111111111111",
      "connector": "least-privilege",
      "endpoint": "https://entitlements.internal",
      "token_ref": "secret://connectors/right-size-token"
    }]
  }
}
```

Local action commands must be absolute, executable, regular non-symlink files.
Unix shell interpreters are rejected. The one native-administration exception is
IIS PowerShell: its profile must pin the complete connector `logical_args`, set a
separate complete operator-owned `args` list, and leave `pass_args` false. The
runtime compares the connector request with that fixed logical argv and executes
only the fixed operator argv, so target data never becomes PowerShell source text.

`connectors.right_size` binds one tenant plus the playbook's connector name to an
operator endpoint and a same-tenant encrypted-secret reference. The durable
`connector.right_size` worker sends an idempotent `PATCH`, verifies the vendor's
mutation receipt, performs an authenticated `GET` readback, and only then records a
delivered connector receipt. Store the referenced token through the tenant secrets
surface (`secrets.enable_api=true`) before enabling the binding. An unconfigured
tenant/connector pair fails closed.

External-CA credentials use `file:/absolute/path` references. Files are loaded into
locked memory for one outbox attempt and wiped afterward. Network policy, private
CIDRs, custom roots, and mTLS identities are operator-owned:

```json
{
  "external_cas": [{
    "id": "aws-pca-prod",
    "type": "awspca",
    "name": "Production AWS Private CA",
    "endpoint": "https://acm-pca.us-east-1.amazonaws.com",
    "region": "us-east-1",
    "certificate_authority_arn": "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/UUID",
    "access_key_id": "AKIA...",
    "secret_access_key_ref": "file:/run/secrets/aws-pca-secret",
    "network": {"timeout": "15s"}
  }, {
    "id": "azure-managed-hsm-ca",
    "type": "azurekv",
    "name": "Azure Managed HSM Issuing CA",
    "tenant_id": "11111111-1111-4111-8111-111111111111",
    "endpoint": "https://production.managedhsm.azure.net",
    "managed_key_ref": "https://production.managedhsm.azure.net/keys/issuing-ca/0123456789abcdef",
    "ca_cert_file": "/etc/trstctl/azure-issuing-ca-chain.pem",
    "network": {"timeout": "15s"}
  }, {
    "id": "entrust-prod",
    "type": "entrust",
    "name": "Entrust CA Gateway",
    "endpoint": "https://entrust-ca.internal",
    "ca_id": "production-ca",
    "network": {
      "root_ca_file": "/etc/trstctl/entrust-server-ca.pem",
      "client_cert_file": "/etc/trstctl/entrust-client.pem",
      "client_key_file": "/run/secrets/entrust-client-key.pem",
      "server_name": "entrust-ca.internal",
      "timeout": "15s"
    }
  }, {
    "id": "letsencrypt-prod",
    "type": "letsencrypt",
    "name": "Let's Encrypt",
    "directory_url": "https://acme-v02.api.letsencrypt.org/directory"
  }, {
    "id": "shell-ca-prod",
    "type": "shellca",
    "name": "Isolated Shell CA",
    "command": "/usr/local/libexec/trstctl-shell-ca",
    "args": ["--profile", "production"],
    "env_refs": {"CA_TOKEN": "file:/run/secrets/shell-ca-token"},
    "network": {"timeout": "15s"}
  }]
}
```

External-CA endpoints require HTTPS. The separate
`network.allow_insecure_http` escape hatch is accepted only for an HTTP
`localhost`, `127/8`, or `::1` development emulator; the runtime client also
refuses any non-loopback resolution or cross-origin/scheme-changing redirect.
`allow_private_endpoint` and private CIDR grants never authorize plaintext.

The Azure CA block carries only routing and public trust material. `tenant_id`
binds the authority to one tenant, `managed_key_ref` is the opaque HTTPS key id
returned by that tenant's managed-key lifecycle, and `ca_cert_file` is the public
issuer chain whose leaf public key must match the managed key. Do not put an Azure
bearer token, `key_name`, or `key_version` in `external_cas`: Azure credentials and
private-key operations live in the isolated signer's `managed_keys` backend.

Let's Encrypt account JWS signatures also cross the signer transport. The control
plane derives a stable account handle from the external-CA id and directory URL,
but it receives only the public key and signatures; the ECDSA account private key
never enters the HTTP process.

Entrust always requires the complete `network` mTLS identity shown above. The
client pins `root_ca_file`, verifies `server_name`, and presents the paired client
certificate/key. Missing, partial, or untrusted client material fails before an
Entrust enrollment request is sent; plaintext HTTP is not an Entrust mode.

For `shellca`, each `env_refs` key is a logical credential name, not a secret-valued
environment variable. The child sees `CA_TOKEN_FD=<number>` and reads the exact
credential bytes from that inherited anonymous pipe. It never receives `CA_TOKEN`,
and trstctl consumes and wipes the byte buffer after the one child attempt. No
credential pathname or filesystem-backed secret copy is created for the child.

Supported `type` values are `adcs`, `awspca`, `azurekv`, `digicert`, `ejbca`,
`entrust`, `gcpcas`, `globalsign`, `letsencrypt`, `sectigo`, `shellca`,
`smallstep`, `vaultpki`, and `venafi`. `trstctl -check-config` validates every
provider's required fields before the server accepts traffic. The exact connector
target schemas are listed in [Deployment connectors](features/deployment-connectors.md).

## Notifications

Notification channels are off until an operator configures them. When enabled, lifecycle
expiry alerts are written to the `notification.*` outbox first, then delivered by the
registered channel workers. Tenant-scoped routing policy authoring and channel-test
delivery are served from the console; channel secrets remain in operator-managed secret
references or files.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_NOTIFICATIONS_EMAIL_ENABLED` | `false` | Enable SMTP email delivery. |
| `TRSTCTL_NOTIFICATIONS_EMAIL_SMTP_ADDR` | empty | SMTP relay `host:port`. |
| `TRSTCTL_NOTIFICATIONS_EMAIL_FROM` | empty | RFC 5322 From address. |
| `TRSTCTL_NOTIFICATIONS_EMAIL_TO` | empty | Comma-separated recipient addresses. |
| `TRSTCTL_NOTIFICATIONS_EMAIL_USERNAME` | empty | Optional SMTP username. |
| `TRSTCTL_NOTIFICATIONS_EMAIL_PASSWORD` / `TRSTCTL_NOTIFICATIONS_EMAIL_PASSWORD_FILE` | empty | Optional SMTP password as bytes or a file. |
| `TRSTCTL_NOTIFICATIONS_SLACK_ENABLED` | `false` | Enable Slack incoming-webhook delivery. |
| `TRSTCTL_NOTIFICATIONS_SLACK_WEBHOOK_URL` | empty | Slack incoming-webhook URL. |
| `TRSTCTL_NOTIFICATIONS_TEAMS_ENABLED` | `false` | Enable Microsoft Teams incoming-webhook delivery. |
| `TRSTCTL_NOTIFICATIONS_TEAMS_WEBHOOK_URL` | empty | Teams webhook URL. |
| `TRSTCTL_NOTIFICATIONS_SMS_ENABLED` | `false` | Enable SMS gateway delivery. |
| `TRSTCTL_NOTIFICATIONS_SMS_ENDPOINT` | empty | HTTPS endpoint for the operator SMS gateway. |
| `TRSTCTL_NOTIFICATIONS_SMS_FROM` | empty | Optional sender label or number. |
| `TRSTCTL_NOTIFICATIONS_SMS_TO` | empty | Comma-separated SMS recipients. |
| `TRSTCTL_NOTIFICATIONS_SMS_TOKEN` / `TRSTCTL_NOTIFICATIONS_SMS_TOKEN_FILE` | empty | Optional gateway bearer token as bytes or a file. |
| `TRSTCTL_NOTIFICATIONS_SIEM_ENABLED` | `false` | Enable SIEM collector delivery. |
| `TRSTCTL_NOTIFICATIONS_SIEM_ENDPOINT` | empty | HTTPS endpoint for the SIEM collector or forwarding gateway. |
| `TRSTCTL_NOTIFICATIONS_SIEM_TOKEN` / `TRSTCTL_NOTIFICATIONS_SIEM_TOKEN_FILE` | empty | Optional collector bearer token as bytes or a file. |
| `TRSTCTL_NOTIFICATIONS_SIEM_SOURCE` | `trstctl` | Source label in SIEM events. |
| `TRSTCTL_NOTIFICATIONS_PAGERDUTY_ENABLED` | `false` | Enable native PagerDuty Events API v2 delivery. |
| `TRSTCTL_NOTIFICATIONS_PAGERDUTY_ENDPOINT` | PagerDuty public Events v2 endpoint | Override the enqueue URL; production endpoints must use HTTPS. |
| `TRSTCTL_NOTIFICATIONS_PAGERDUTY_ROUTING_KEY` / `TRSTCTL_NOTIFICATIONS_PAGERDUTY_ROUTING_KEY_FILE` | empty | PagerDuty integration routing key. Set exactly one when enabled; the file form keeps the key out of the environment. |
| `TRSTCTL_NOTIFICATIONS_PAGERDUTY_TIMEOUT` | `10s` | Bounded Events API request deadline. |
| `TRSTCTL_NOTIFICATIONS_PAGERDUTY_ALLOW_PRIVATE_CIDRS` | empty | Comma-separated exact private CIDRs allowed by the SSRF-safe client for an operator-run gateway. |
| `TRSTCTL_NOTIFICATIONS_OPSGENIE_ENABLED` | `false` | Enable native OpsGenie Alert API v2 delivery. |
| `TRSTCTL_NOTIFICATIONS_OPSGENIE_ENDPOINT` | OpsGenie public Alert API endpoint | Override the create-alert URL; production endpoints must use HTTPS. |
| `TRSTCTL_NOTIFICATIONS_OPSGENIE_API_KEY` / `TRSTCTL_NOTIFICATIONS_OPSGENIE_API_KEY_FILE` | empty | OpsGenie API key. Set exactly one when enabled; the file form keeps the key out of the environment. |
| `TRSTCTL_NOTIFICATIONS_OPSGENIE_TIMEOUT` | `10s` | Bounded Alert API request deadline. |
| `TRSTCTL_NOTIFICATIONS_OPSGENIE_ALLOW_PRIVATE_CIDRS` | empty | Comma-separated exact private CIDRs allowed by the SSRF-safe client for an operator-run gateway. |

PagerDuty and OpsGenie credentials are copied into locked, non-dumpable memory at
startup and wiped on shutdown. Both integrations send deterministic vendor idempotency
identifiers, require the vendor's exact acceptance receipt, and redact remote error
bodies. `*_ALLOW_INSECURE_HTTP` exists only for a loopback development emulator; even
when set, it cannot enable cleartext delivery to a non-loopback host.

## Code signing

The shipped code-signing routes stay fail-closed until `code_signing.enabled` is true.
Tenant-to-key and tenant-to-OIDC associations are structured JSON only: putting these
parallel lists in environment variables increase the risk of attaching one tenant's
trust to another tenant. A minimal key-backed plus GitHub Actions keyless configuration
looks like this:

```json
{
  "code_signing": {
    "enabled": true,
    "keys": [{
      "tenant_id": "tenant-acme",
      "id": "release-key",
      "handle": "acme-release-code-signing",
      "algorithm": "ecdsa-p256",
      "create_if_missing": true
    }],
    "github_oidc_tenants": [{
      "tenant_id": "tenant-acme",
      "issuer": "https://token.actions.githubusercontent.com",
      "audience": "sigstore",
      "jwks_file": "/run/trstctl/github-actions-jwks.json",
      "allowed_owners": ["acme"]
    }],
    "ephemeral_algorithm": "ecdsa-p256",
    "rekor": {
      "endpoint": "https://rekor.example.com/api/v1/log/entries",
      "timeout": "10s",
      "log_public_key_file": "/run/trstctl/rekor-log-public-key.pem"
    }
  }
}
```

`create_if_missing` provisions a `code-sign`-purpose-constrained handle inside the
separate signer process; the control plane never receives the private key. Keyless
requests also create and destroy their one-use key inside that signer. Pin the Rekor
log public key from the Rekor operator's authenticated distribution channel. Startup
fails if this trust anchor is absent or malformed, and every outbox delivery verifies
the returned signed-entry timestamp against it before acknowledging the row.

Code signing uses the shared live policy controls rather than a decorative, code-only
allow list. With `ca.policy.enabled=true`, OPA receives action `code_sign`, the
authenticated actor, the configured key ID (or `keyless:<verified-san>`), and
`attrs.digest_sha256`; evaluation errors and policy-pool saturation fail closed. With
`ca.policy.require_approval=true`, a denied response returns
`approval_required:codesign:<sha256>`. A distinct `certs:issue` approver posts
`{"action":"sign"}` to `/api/v1/identities/{that-resource}/approvals`, after which the
requester retries the same signing tuple with a new `Idempotency-Key`. The resource hash
binds tenant, authenticated requester, key/keyless identity, and exact digest.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_CODE_SIGNING_ENABLED` | `false` | Enable production assembly of the served key-backed and keyless routes. |
| `TRSTCTL_CODE_SIGNING_EPHEMERAL_ALGORITHM` | `ecdsa-p256` | Algorithm for isolated one-use keyless keys; currently only P-256 is accepted. |
| `TRSTCTL_CODE_SIGNING_REKOR_ENDPOINT` | Sigstore public Rekor v1 endpoint | HashedRekord create endpoint. Production endpoints must use HTTPS. |
| `TRSTCTL_CODE_SIGNING_REKOR_TIMEOUT` | `10s` | Bounded create/readback deadline. |
| `TRSTCTL_CODE_SIGNING_REKOR_LOG_PUBLIC_KEY_FILE` | empty | Required PEM PKIX public key used to verify Rekor signed-entry timestamps. |
| `TRSTCTL_CODE_SIGNING_REKOR_ALLOW_PRIVATE_CIDRS` | empty | Comma-separated exact private CIDRs allowed for an operator-run Rekor deployment. |

`TRSTCTL_CODE_SIGNING_REKOR_ALLOW_INSECURE_HTTP` is accepted only for a loopback
development emulator. It cannot relax transport security for a remote Rekor service.

## Telemetry

Telemetry is **off by default** and never sends anything unless you opt in. When
enabled, it sends only coarse, anonymized, non-PII data to a collector you name.
The project operates no public telemetry collector, so there is no default
endpoint: enabling telemetry without `TRSTCTL_TELEMETRY_ENDPOINT` is a
configuration error and trstctl refuses to start.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_TELEMETRY_ENABLED` | `false` | Set `true` to opt in. A malformed value is ignored (stays off). |
| `TRSTCTL_TELEMETRY_ENDPOINT` | empty | Required when telemetry is enabled; must be an absolute `https` URL for a collector you operate. There is no default. |
| `TRSTCTL_TELEMETRY_INTERVAL` | `24h` | Reporting interval. |
| `TRSTCTL_TELEMETRY_INSTANCE_ID_FILE` | `data/telemetry/instance-id` | Local file holding the random anonymous instance ID. Required when telemetry is enabled. |

See [Telemetry](telemetry.md) for exactly what is and is not collected.

## Air-gap and outbound egress

Air-gap mode arms the no-phone-home outbound HTTP(S) guard. It is off by default;
when enabled, public destinations are blocked unless you explicitly allow a host
or CIDR. It is intended for disconnected networks and is paired with the Helm
`values-airgap.yaml` overlay described in [Air-gapped install](airgap.md).

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_AIRGAP_ENABLED` | `false` | Set `true` to deny public outbound HTTP(S) unless a host or CIDR is allowlisted. |
| `TRSTCTL_AIRGAP_ALLOW_PRIVATE` | `true` | Allows loopback, private, and link-local IP destinations. Leave true for private PostgreSQL/NATS/OTLP/local model endpoints. |
| `TRSTCTL_AIRGAP_ALLOW_HOSTS` | — | Comma-separated host allowlist for operator-owned local services such as `otel-collector.observability.svc`. Hosts only; URLs are rejected. |
| `TRSTCTL_AIRGAP_ALLOW_CIDRS` | — | Comma-separated CIDR allowlist for private service ranges, e.g. `10.0.0.0/8,172.16.0.0/12`. Invalid CIDRs fail startup. |
| `TRSTCTL_OUTBOUND_ENV_CREDENTIAL_REFS` | — | Comma-separated `env:NAME` references that API-authored discovery, response-integration, and scheduled audit-feed requests may use for outbound credentials. Unknown env refs are rejected before event/outbox enqueue. |

When `TRSTCTL_AIRGAP_ENABLED=true`, trstctl rejects
`TRSTCTL_TELEMETRY_ENABLED=true` and `TRSTCTL_AI_MODEL_MODE=cloud` at startup.
Local OTLP collectors and local AI runtimes are still allowed when their hosts or
CIDRs are private or explicitly allowlisted.

### Scheduled Splunk HEC and Sentinel audit feeds

Audit-feed schedules are tenant configuration, not process-global environment
settings. Review the exact candidate first with `POST
/api/v1/audit/feeds/{id}/preview`, `trstctl-cli audit feeds preview`, or the Audit
console. Preview runs the same server validator as save but creates no event, feed
row, idempotency record, outbox row, or network call. Save only after the review
shows the expected collector host, non-secret credential reference, permission,
durable writes, later external effect, proof, and recovery steps. Saving uses `PUT
/api/v1/audit/feeds/{id}`, `trstctl-cli audit feeds set`, or the Audit console.
Each request chooses `splunk-hec` or `sentinel`, an absolute endpoint URL, an
interval of at least 60 seconds, and an exact maximum batch size from 1 through
500.

The request stores only an `env:NAME` pointer. Put that pointer in
`TRSTCTL_OUTBOUND_ENV_CREDENTIAL_REFS`, then inject the named environment variable
into the control-plane process. The secret value is read only by the delivery
worker; it never enters the configuration event, projection, API response, log, or
collector error receipt. Public HTTPS is the default. A private endpoint also
requires the caller's private-egress permission plus exact `private_egress_cidrs`;
the SSRF-safe client rejects addresses outside that tenant configuration.

The scheduler does no network I/O. It commits `audit.feed.batch.queued`, the exact
sequence range and record IDs, the destination projection, and one deterministic
outbox intent before a worker can call the collector. A retry or restart therefore
uses the same batch ID and bytes. `GET /api/v1/audit/feeds` exposes the delivered
cursor, persistent record-count lag, attempts, next retry, terminal error code,
and collector request ID without exposing response bodies or credentials.
Failed delivery retains the exact batch and delivered cursor. Automatic retry
reuses the same durable batch ID and idempotency key; the cursor advances only
after the collector accepts that exact batch. Disable the feed to stop scheduling
new batches while retaining failure and delivery evidence.

## ITSM and ServiceNow bindings

ServiceNow ticket creation is fail-closed until an operator pre-registers the
destination URL and credential reference. Requests to
`/api/v1/itsm/servicenow/tickets` and ServiceNow response-dispatch destinations must
match that binding exactly; callers cannot send the ServiceNow token to an arbitrary
`instance_url` or opt into a private endpoint unless the binding permits it.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_SERVICENOW_INSTANCE_URL` | — | Approved ServiceNow instance base URL, for example `https://example.service-now.com`. |
| `TRSTCTL_SERVICENOW_TOKEN_REF` | `env:TRSTCTL_SERVICENOW_TOKEN` when an instance URL is set | Credential reference resolved by the outbox worker. This is a reference, not the token value. |
| `TRSTCTL_SERVICENOW_ALLOW_PRIVATE_ENDPOINT` | `false` | Allows an approved `http://` or private endpoint binding for lab/private ServiceNow gateways. Leave false for normal hosted ServiceNow. |
| `TRSTCTL_SERVICENOW_PRIVATE_EGRESS_CIDRS` | — | Comma-separated CIDR grants for a private ServiceNow binding. Required when `TRSTCTL_SERVICENOW_ALLOW_PRIVATE_ENDPOINT=true`. |

JSON config supports the same policy as `itsm.servicenow.bindings[]` with
`instance_url`, `token_ref`, `allow_private_endpoint`, and
`private_egress_cidrs`. Private endpoint requests also require the caller to hold
the dedicated `egress:private` permission.

## OpenTelemetry export

OTLP export is **off by default** and sends data only to the collector endpoint you
configure. It is separate from product telemetry: use it to feed your own
OpenTelemetry Collector, Splunk, Datadog, or SIEM pipeline with served HTTP traces
and audit-event log records.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_OTLP_ENABLED` | `false` | Set `true` to enable OTLP/HTTP protobuf export. |
| `TRSTCTL_OTLP_ENDPOINT` | — | Absolute collector URL. HTTPS is required unless `TRSTCTL_OTLP_INSECURE=true`; the exporter posts to `/v1/traces` and `/v1/logs` under this base. |
| `TRSTCTL_OTLP_INSECURE` | `false` | Allows plaintext `http://` collector endpoints for local or private-network deployments. |
| `TRSTCTL_OTLP_BEARER_TOKEN` | — | Optional collector bearer token. Prefer the file setting for production secret mounts. |
| `TRSTCTL_OTLP_BEARER_TOKEN_FILE` | — | Optional file containing the collector bearer token. Mutually exclusive with `TRSTCTL_OTLP_BEARER_TOKEN`. |
| `TRSTCTL_OTLP_TIMEOUT` | `5s` | Per-export HTTP timeout. |
| `TRSTCTL_OTLP_QUEUE_SIZE` | `1024` | Bounded trace-export queue size. Full queues drop spans rather than slowing served API requests. |
| `TRSTCTL_OTLP_SERVICE_NAME` | `trstctl` | `service.name` resource attribute sent to the collector. |

In air-gap mode, point OTLP at an operator-owned collector on a private address or
add the collector host to `TRSTCTL_AIRGAP_ALLOW_HOSTS`; public collector SaaS
endpoints are blocked by the egress guard.

## Audit

The audit trail is a projection of the event log; these settings govern its
evidence **export** and **retention** policy. See [Audit trail &
compliance](compliance.md) for the trust model and what trstctl enables vs. what
you must operate.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_AUDIT_SIGNING_KEY_FILE` | `data/audit/signing-key.pem` | **Upgrade migration path only.** If this historical PEM exists, the isolated `trstctl-signer` imports it into the sealed, purpose-constrained `audit-export` handle and deletes the plaintext after durable persistence. Fresh deployments never create this file. In external-signer mode, mount the legacy path into the signer and pass `--legacy-audit-key`; the control plane refuses to rotate around a leftover PEM. |
| `TRSTCTL_AUDIT_RETENTION` | — (indefinite) | Served audit-view window, a Go duration (e.g. `8760h`). Empty means **indefinite** (the default). When set **and** `TRSTCTL_AUDIT_ARCHIVE_DIR` is given, a background worker archives older records to signed bundles, verifies the bundle, and advances a replayable tenant checkpoint so those records leave the live query view. Their underlying AN-2 event envelopes remain retained for projection rebuild, disaster recovery, and authorized privacy rewrite. |
| `TRSTCTL_AUDIT_ARCHIVE_DIR` | — | Cold-storage directory for the signed archive bundles (`<dir>/<tenant>/audit-<seq>.jws`, `0600`). **Required to advance the served-view retention floor**; without it the view remains indefinite. Point it at WORM-backed storage you protect. See [Audit retention and archive lifecycle](compliance.md#audit-retention-and-archive-lifecycle). |

The audit query (`/api/v1/audit/events`) and signed export (`/api/v1/audit/export`)
endpoints are wired into the serving binary, so they return real data — not an
error — out of the box. The evidence private key lives only in the signer's
sealed key store; back up that store and the KEK, and distribute the public JWKS
to auditors out of band.

## Privacy Retention

Non-audit personal data is retained by class, then pseudonymized after the
operational need ends. This is separate from audit retention: the immutable event
trail remains the source of truth, while tenant read surfaces stop carrying stale
names, emails, subjects, SANs, comments, profile authors, approval actors, and
free-form evidence. The worker emits `privacy.retention.enforced` and projects the
anonymization from that event, so rebuilds replay the same result.

Subject erasure also pseudonymizes matching raw subject bytes in the hot JetStream
event store. The control plane records `privacy.subject.erased`, builds a
sequence-preserving replacement generation with the erased subject changed to its
tenant-bound `erased:<subject_ref>` placeholder, and signs the old/new continuity
evidence before switching authority. The old generation remains authoritative if
the operation stops before that switch; only after the signed replacement is active
are its superseded subject bytes securely scrubbed. Replay, projection tailing,
retention, and backups share a history barrier with that cutover. This keeps future
hot-log replay, audit queries, and full backups taken after the erasure from carrying
the raw subject without ever purging and rebuilding the sole authoritative stream.
Backups and signed audit archives created before the erasure are not rewritten
automatically. Record the outcome of your legal-hold, WORM,
backup-deletion, or cryptographic-shredding procedure with
`POST /api/v1/privacy/archive-erasure-attestations`; inspect the tenant evidence
ledger with `GET /api/v1/privacy/archive-erasure-attestations` or
`trstctl privacy archives attest/list`. The attestation event stores
`subject_ref` and redacted evidence refs, not the raw subject.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_PRIVACY_RETENTION_ENABLED` | `true` | Runs the leader-only non-audit PII retention worker. Set `false` only when an external privacy job enforces the same policy. |
| `TRSTCTL_PRIVACY_RETENTION_INTERVAL` | `24h` | Worker cadence. It also runs once on startup. |
| `TRSTCTL_PRIVACY_RETENTION_OWNERS` | `17520h` (730 days) | Pseudonymize owner name/email when the owner is older than this and no identity references it. |
| `TRSTCTL_PRIVACY_RETENTION_IDENTITIES` | `9528h` (397 days) | Pseudonymize terminal or expired identity metadata. |
| `TRSTCTL_PRIVACY_RETENTION_CERTIFICATES` | `9528h` (397 days) | Pseudonymize expired/revoked/superseded certificate subject, SAN, deployment location, and source metadata. |
| `TRSTCTL_PRIVACY_RETENTION_SSH_KEYS` | `4320h` (180 days) | Clear orphaned stale SSH key comments and locations. |
| `TRSTCTL_PRIVACY_RETENTION_ACCESS` | `2160h` (90 days) | Pseudonymize offboarded tenant members and expired/revoked API-token subjects. |
| `TRSTCTL_PRIVACY_RETENTION_APPROVALS` | `9528h` (397 days) | Pseudonymize old requester/approver subject values while preserving resource/action evidence. |
| `TRSTCTL_PRIVACY_RETENTION_PROFILES` | `9528h` (397 days) | Pseudonymize old certificate-profile author values. |
| `TRSTCTL_PRIVACY_RETENTION_ATTESTATIONS` | `9528h` (397 days) | Clear stale free-form attestation evidence JSON. |
| `TRSTCTL_PRIVACY_RETENTION_AGENTS` | `4320h` (180 days) | Pseudonymize stale agent names while preserving agent id, status, version, and heartbeat timestamps. |

Operators can trigger and inspect the same served path with
`POST /api/v1/privacy/retention-runs`, `GET /api/v1/privacy/retention-runs`, or
the matching `trstctl privacy retention run/list` CLI commands.

## Provider workforce identity and customer access

The Provider plane is a different privilege domain from tenant login. OIDC or
SAML proves which Provider employee is calling. SCIM is the live joiner/leaver
directory. A customer delegation then narrows that active employee to one
customer and one operation. Think of the chain as three locks: a request opens
only when identity, employment state, and exact customer authority all agree.

OIDC verifies an offline-pinned JWKS plus issuer, audience, time, mapped role,
and MFA. SAML serves login, ACS, and metadata at
`/provider/v1/auth/saml/{login,acs,metadata}` and verifies signed assertions
inside `internal/crypto`. Its HttpOnly cookie is Provider-only and mutations use
double-submit CSRF. When Provider SCIM is enabled, both methods resolve the
SCIM-projected operator on every request, so deprovisioning immediately refuses
an otherwise valid token/session and revokes the operator's live delegations.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_PROVIDER_OIDC_ISSUER` / `TRSTCTL_PROVIDER_OIDC_AUDIENCE` | unset | Required OIDC issuer and audience. |
| `TRSTCTL_PROVIDER_OIDC_JWKS_FILE` / `TRSTCTL_PROVIDER_OIDC_JWKS_JSON` | unset | Exactly one offline-pinned IdP signing-key source. The partner lab's licensed profile pins its local IdP this way (`deploy/demo/lab/docker-compose.licensed.yml`). |
| `TRSTCTL_PROVIDER_OIDC_ROLE_CLAIM` | `roles` | Signed claim containing Provider role values. |
| `TRSTCTL_PROVIDER_OIDC_ADMIN_VALUES` / `TRSTCTL_PROVIDER_OIDC_OPERATOR_VALUES` | unset | Maps signed values to the two Provider roles. |
| `TRSTCTL_PROVIDER_OIDC_MFA_CLAIM` / `TRSTCTL_PROVIDER_OIDC_MFA_VALUES` | `amr` / `mfa,otp,hwk,swk` | Signed claim and accepted values that positively prove MFA. |
| `TRSTCTL_PROVIDER_SAML_ENABLED` | `false` | Enables the separate Provider SAML SP. |
| `TRSTCTL_PROVIDER_SAML_ENTITY_ID` / `TRSTCTL_PROVIDER_SAML_METADATA_URL` / `TRSTCTL_PROVIDER_SAML_ACS_URL` | unset | HTTPS SP identity and served endpoint URLs. |
| `TRSTCTL_PROVIDER_SAML_IDP_METADATA_FILE` / `TRSTCTL_PROVIDER_SAML_IDP_METADATA_XML` | unset | Exactly one offline IdP signing-metadata source. |
| `TRSTCTL_PROVIDER_SAML_SESSION_SECRET_FILE` | unset | Custody-checked file for the Provider session HMAC secret; created with 32 random bytes if absent. |
| `TRSTCTL_PROVIDER_SAML_ROLE_ATTRIBUTE` / `TRSTCTL_PROVIDER_SAML_ADMIN_VALUES` / `TRSTCTL_PROVIDER_SAML_OPERATOR_VALUES` | unset | Assertion attribute and values mapped onto Provider roles. |
| `TRSTCTL_PROVIDER_SAML_MFA_ATTRIBUTE` / `TRSTCTL_PROVIDER_SAML_MFA_VALUES` | unset | Assertion attribute and values that positively prove MFA. |
| `TRSTCTL_PROVIDER_SCIM_ENABLED` | `false` | Serves Provider workforce provisioning at `/provider/scim/v2`. |
| `TRSTCTL_PROVIDER_SCIM_TOKEN_NAME` / `TRSTCTL_PROVIDER_SCIM_TOKEN_FILE` | unset | Audit source name and custody-checked raw bearer-token file. The runtime retains only its SHA-256 hash. |

Multi-token JSON configuration and a complete SAML block:

```json
{
  "provider": {
    "oidc": {
      "issuer": "https://idp.provider.example",
      "audience": "trstctl-provider",
      "jwks_file": "/etc/trstctl/provider-idp.jwks",
      "role_claim": "groups",
      "admin_values": ["provider-admin"],
      "operator_values": ["provider-operator"]
    },
    "saml": {
      "enabled": true,
      "entity_id": "https://trstctl.provider.example/provider/v1/auth/saml/metadata",
      "metadata_url": "https://trstctl.provider.example/provider/v1/auth/saml/metadata",
      "acs_url": "https://trstctl.provider.example/provider/v1/auth/saml/acs",
      "idp_metadata_file": "/etc/trstctl/provider-idp-metadata.xml",
      "session_secret_file": "/var/lib/trstctl/provider-saml-session.secret",
      "role_attribute": "groups",
      "admin_values": ["provider-admin"],
      "operator_values": ["provider-operator"],
      "mfa_attribute": "amr",
      "mfa_values": ["mfa"]
    },
    "scim": {
      "enabled": true,
      "tokens": [
        {"name": "entra", "token_file": "/etc/trstctl/provider-scim-entra.token"}
      ]
    }
  }
}
```

The operator console lists SCIM lifecycle and every current/historical
delegation. Grant/revoke/role mutations require a Provider admin, current MFA,
and `Idempotency-Key`; exact retries return the same event result.

## Browser SSO

Browser sign-on is optional. Scoped API tokens still work when browser sign-on is off.
When it is on, each verified OIDC, SAML, or LDAP / Active Directory user must map to
exactly one trstctl tenant by subject, tenant claim, directory group, or an explicit
single-tenant fallback. Missing mappings fail the login closed instead of silently
dropping a user into the wrong tenant.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_AUTH_OIDC_ENABLED` | `false` | Enables served OIDC login at `/auth/login` and `/auth/callback`. |
| `TRSTCTL_AUTH_OIDC_ISSUER` | unset | Expected OIDC issuer. |
| `TRSTCTL_AUTH_OIDC_AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED` | `false` | Requires the callback `iss` parameter to match the issuer when the IdP advertises RFC 9207 support. |
| `TRSTCTL_AUTH_OIDC_CLIENT_ID` | unset | Expected OIDC audience / client id. |
| `TRSTCTL_AUTH_OIDC_CLIENT_SECRET` | unset | Inline confidential-client secret for the code→token exchange. Required for a confidential client unless the tenant-scoped credential-store reference below is used instead; a public/PKCE client may leave it empty. |
| `TRSTCTL_AUTH_OIDC_CLIENT_SECRET_TENANT` / `TRSTCTL_AUTH_OIDC_CLIENT_SECRET_REF` | unset | Reads a confidential-client secret from the encrypted tenant-scoped credential store at `(tenant, auth.oidc, ref, client_secret)`. |
| `TRSTCTL_AUTH_OIDC_AUTH_ENDPOINT` | unset | The IdP's authorization endpoint the browser is redirected to. Required. |
| `TRSTCTL_AUTH_OIDC_TOKEN_ENDPOINT` | unset | The IdP's token endpoint the callback exchanges the authorization code at. Required. |
| `TRSTCTL_AUTH_OIDC_REDIRECT_URI` | unset | External callback URL, usually `https://trstctl.example.com/auth/callback`. |
| `TRSTCTL_AUTH_OIDC_JWKS_FILE` / `TRSTCTL_AUTH_OIDC_JWKS_JSON` | unset | IdP signing keys used for offline id_token verification. |
| `TRSTCTL_AUTH_SAML_ENABLED` | `false` | Enables the served SAML 2.0 SP. |
| `TRSTCTL_AUTH_SAML_ENTITY_ID` | unset | Stable SP entity ID, often the metadata URL. |
| `TRSTCTL_AUTH_SAML_METADATA_URL` | unset | External URL for `/auth/saml/metadata`. |
| `TRSTCTL_AUTH_SAML_ACS_URL` | unset | External assertion consumer service URL for `/auth/saml/acs`. |
| `TRSTCTL_AUTH_SAML_IDP_METADATA_FILE` / `TRSTCTL_AUTH_SAML_IDP_METADATA_XML` | unset | IdP metadata XML containing the signing certificate. |
| `TRSTCTL_AUTH_SAML_SESSION_SECRET_FILE` | unset | HMAC secret file used to sign browser sessions. |
| `TRSTCTL_AUTH_SAML_TENANT_CLAIM` | unset | SAML attribute whose value feeds tenant mapping. |
| `TRSTCTL_AUTH_SAML_GROUPS_CLAIM` | unset | SAML attribute whose values feed group-to-tenant mapping. |
| `TRSTCTL_AUTH_LDAP_ENABLED` | `false` | Enables served LDAP / Active Directory login at `POST /auth/ldap/login`. |
| `TRSTCTL_AUTH_LDAP_URL` | unset | Directory URL. Use `ldaps://` for production; `ldap://` is accepted only on loopback. |
| `TRSTCTL_AUTH_LDAP_USER_DN_TEMPLATE` | unset | Direct-bind DN template such as `uid={username},ou=people,dc=example,dc=org`. |
| `TRSTCTL_AUTH_LDAP_BIND_DN` / `TRSTCTL_AUTH_LDAP_BIND_PASSWORD_FILE` | unset | Optional read-only service bind for user and group searches. |
| `TRSTCTL_AUTH_LDAP_USER_SEARCH_BASE_DN` / `TRSTCTL_AUTH_LDAP_USER_FILTER` | unset | User lookup when no direct-bind template is used. |
| `TRSTCTL_AUTH_LDAP_GROUP_SEARCH_BASE_DN` / `TRSTCTL_AUTH_LDAP_GROUP_FILTER` | unset | Group lookup; `{user_dn}` and `{username}` are escaped before search. |
| `TRSTCTL_AUTH_LDAP_GROUP_NAME_ATTRIBUTE` | unset | Group attribute mapped to `tenant_mappings[].group`, usually `cn`. |
| `TRSTCTL_AUTH_LDAP_SESSION_SECRET_FILE` | unset | HMAC secret file used to sign browser sessions. |

## SCIM provisioning

SCIM 2.0 provisioning is optional and separate from browser sign-on. Enable it when
your identity provider should push users and groups into trstctl instead of an
operator maintaining role membership by hand. The served endpoint is `/scim/v2`:
IdPs use `POST /scim/v2/Users`, `PATCH /scim/v2/Users/{id}`,
`POST /scim/v2/Groups`, and `PATCH /scim/v2/Groups/{id}`.

Each SCIM bearer token is bound to exactly one tenant in config. trstctl reads the raw
token from `auth.scim.tokens[].token_file`, hashes it at startup, wipes the raw bytes,
and keeps only the hash. The token selects the tenant for every SCIM request; tenant
ids in SCIM payloads are ignored. Groups map to configured RBAC role names, so an IdP
group with display name `viewer` grants the built-in `viewer` role to its members.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_AUTH_SCIM_ENABLED` | `false` | Enables the served SCIM 2.0 provisioning surface under `/scim/v2`. |
| `TRSTCTL_AUTH_SCIM_TOKEN_NAME` | `scim` | Human label used in audit actor metadata for the single env-configured token. |
| `TRSTCTL_AUTH_SCIM_TOKEN_TENANT_ID` | unset | Tenant this SCIM token may provision. Required when SCIM is enabled through env. |
| `TRSTCTL_AUTH_SCIM_TOKEN_FILE` | unset | File containing the raw bearer token. Required when SCIM is enabled through env. |

Example multi-token SCIM config:

```yaml
auth:
  scim:
    enabled: true
    tokens:
      - name: okta-payments
        tenant_id: 22222222-2222-2222-2222-222222222222
        token_file: /etc/trstctl/scim/okta-payments.token
      - name: entra-platform
        tenant_id: 33333333-3333-3333-3333-333333333333
        token_file: /etc/trstctl/scim/entra-platform.token
```

Example SAML config:

```yaml
auth:
  saml:
    enabled: true
    entity_id: https://trstctl.example.com/auth/saml/metadata
    metadata_url: https://trstctl.example.com/auth/saml/metadata
    acs_url: https://trstctl.example.com/auth/saml/acs
    idp_metadata_file: /etc/trstctl/idp-metadata.xml
    session_secret_file: /var/lib/trstctl/saml-session.secret
    tenant_claim: tenant
    groups_claim: groups
    tenant_mappings:
      - subject: alice@example.com
        tenant_id: 11111111-1111-1111-1111-111111111111
        roles: [admin]
```

Example LDAP / Active Directory config:

```yaml
auth:
  ldap:
    enabled: true
    url: ldaps://ad.example.com:636
    bind_dn: cn=trstctl-reader,ou=service-accounts,dc=example,dc=com
    bind_password_file: /etc/trstctl/ldap-bind.secret
    user_search_base_dn: ou=people,dc=example,dc=com
    user_filter: "(sAMAccountName={username})"
    group_search_base_dn: ou=groups,dc=example,dc=com
    group_filter: "(member={user_dn})"
    group_name_attribute: cn
    email_attribute: mail
    session_secret_file: /var/lib/trstctl/ldap-session.secret
    tenant_mappings:
      - group: payments-trstctl-admins
        tenant_id: 22222222-2222-2222-2222-222222222222
        roles: [admin]
```

## ABAC deny overlay

ABAC is an optional deny-only overlay on top of RBAC. RBAC must grant the permission
first; the ABAC Rego module can then block the request using request attributes,
identity tags, operator-provided environment state, and time. This is useful for rules
such as "prod certs may issue only during change windows" or "break-glass actions may
run only from the platform project."

The module must declare `package trstctl.abac`, define boolean `deny`, and may define
string `reason`. Bad Rego fails startup. Runtime evaluation errors deny the request, and
policy-worker saturation returns `503` instead of allowing.

In a config file, the keys are `auth.abac.enabled`, `auth.abac.module`, and
`auth.abac.environment`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_AUTH_ABAC_ENABLED` | `false` | Enables the ABAC deny overlay after RBAC on guarded API routes and on served issue/deploy/revoke lifecycle decisions. |
| `TRSTCTL_AUTH_ABAC_MODULE` | unset | Inline Rego module with `package trstctl.abac`, boolean `deny`, and optional string `reason`. Required when ABAC is enabled. |
| `TRSTCTL_AUTH_ABAC_ENVIRONMENT` | unset | Comma-separated operator state copied into `input.env`, for example `change_window=true,region=us-east-1`. |

Example ABAC config:

```yaml
auth:
  abac:
    enabled: true
    environment:
      change_window: "false"
    module: |
      package trstctl.abac
      default deny := false
      default reason := ""

      deny if {
        input.permission == "certs:issue"
        input.resource.env == "prod"
        input.env.change_window != "true"
      }

      reason := "prod certificates may issue only during a change window" if {
        deny
      }
```

## Break-glass lifecycle and reconciliation

Break-glass emergency issuance has two served paths. `POST /api/v1/breakglass/issue`
performs online m-of-n emergency issuance when a signer-backed break-glass issuer is
configured. First open the exact CSR/reason/TTL ceremony at
`POST /api/v1/breakglass/issue-ceremonies`; then distinct configured operators approve
that ceremony through the shared authenticated CA-approval route. The execution
request carries `ceremony_id` and no approver names. The server derives quorum only
from immutable `ca.ceremony.approved` event actors, consumes the ceremony once,
returns a self-verifying bundle, and records `breakglass.issued` before responding.
The same signer-backed lifecycle exposes purpose-bound rotation and target-CA
cross-sign ceremony/execution pairs under `/api/v1/breakglass/*-ceremonies`,
`/api/v1/breakglass/rotate`, and `/api/v1/breakglass/cross-sign`.
`POST /api/v1/breakglass/reconcile` handles recovery after an offline ceremony: it
accepts signed offline bundles, verifies them against trust anchors pinned in process
config, and records verified facts as `breakglass.issued` events in the hash-chained
audit log. Requests cannot supply their own verifier keys.

`breakglass.enabled` pins reconciliation verifier material. The files may be DER, or
PEM with `CERTIFICATE` and `PUBLIC KEY` blocks, and startup fails closed when either
is missing or unreadable. `breakglass.online_enabled` additionally requires one
tenant, an already-persisted dual-control signer handle whose public key matches both
files, a distinct operator roster, and a threshold of at least two. Reconciliation-
only deployments do not need the online fields.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_BREAKGLASS_ENABLED` | `false` | Enables verifier material for `POST /api/v1/breakglass/reconcile`. |
| `TRSTCTL_BREAKGLASS_ONLINE_ENABLED` | `false` | Enables signer-backed issue, rotation, and cross-sign routes. Requires `enabled=true` and all custody/quorum fields below. |
| `TRSTCTL_BREAKGLASS_CA_CERT_FILE` | unset | DER or PEM CA certificate that emergency bundle certificates must chain to. Required when enabled. |
| `TRSTCTL_BREAKGLASS_PUBLIC_KEY_FILE` | unset | DER or PEM public key that verifies the emergency bundle manifest signature. Required when enabled. |
| `TRSTCTL_BREAKGLASS_TENANT_ID` | unset | The only tenant allowed to use the online break-glass signer. |
| `TRSTCTL_BREAKGLASS_SIGNER_HANDLE` | unset | Existing purpose-constrained, dual-control signer handle whose public key must match the configured CA and public-key file. |
| `TRSTCTL_BREAKGLASS_OPERATORS` | unset | Comma-separated authenticated operator subjects allowed to count toward quorum. |
| `TRSTCTL_BREAKGLASS_THRESHOLD` | `0` | Required m-of-n threshold; online mode requires at least `2` and no more than the number of distinct configured operators. |

Example break-glass reconciliation config:

```yaml
breakglass:
  enabled: true
  ca_cert_file: /etc/trstctl/breakglass-ca.pem
  public_key_file: /etc/trstctl/breakglass-public-key.pem
```

Online lifecycle adds the custody and roster fields:

```yaml
breakglass:
  enabled: true
  online_enabled: true
  ca_cert_file: /etc/trstctl/breakglass-ca.pem
  public_key_file: /etc/trstctl/breakglass-public-key.pem
  tenant_id: 10000000-0000-4000-8000-000000000001
  signer_handle: recovery-breakglass-ca
  operators: [recovery-operator-a, recovery-operator-b, recovery-operator-c]
  threshold: 2
```

To create that handle without a test-only or library-only path, leave
`online_enabled=false`, use `trstctl-cli ca ceremonies start` plus distinct
`ca ceremonies approve` calls, and finish with `ca authorities create-root`. Save
the returned `certificate_pem` and `signer_handle`; derive the public-key file from
the certificate (`openssl x509 -pubkey -noout`), set the online fields above, and
restart. Startup proves the certificate, derived public key, and persisted signer
handle all name the same key before it exposes any online break-glass route.

## Secrets (credentials at rest)

Upstream CA and connector credentials — API keys, passwords, client secrets — are
stored **encrypted at rest** using envelope encryption (R3.1): a fresh random
data-encryption key (DEK) encrypts each credential with AES-256-GCM, and the
**key-encryption key (KEK)** wraps the DEK. Only ciphertext is ever persisted; the
plaintext never appears in the database, in config dumps, or in logs. The
cryptography lives behind the platform's single crypto boundary.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_SECRETS_KEK_FILE` | `data/secrets/kek.bin` | Path to the 256-bit KEK that wraps every stored credential. It is **created `0600` on first boot** if absent, and is the root of trust for credentials at rest. |
| `TRSTCTL_TENANT_SEAL_LOCAL_WRAPPER_ID` | unset | Stable non-secret ID for one operator-provisioned local tenant-domain wrapper. Both this variable and the file variable below are required together. The database stores this ID, never the path or wrapper key. |
| `TRSTCTL_TENANT_SEAL_LOCAL_WRAPPER_FILE` | unset | Existing local wrapper-key file for the ID above. trstctl does **not** create it or fall back to the deployment KEK when it is missing/wrong. Configure multiple wrappers with `secrets.tenant_seal_local_wrappers` in JSON/YAML. |
| `TRSTCTL_IDEMPOTENCY_RESULT_FLEET_READY` | `false` | Operator assertion that **every** process writing this PostgreSQL database understands `sealed-row-v1` and durable indeterminate claims. After the legacy drain, startup installs a sealed-only PostgreSQL default/constraint. Never enable it while an older writer is running; the ratchet is deliberately incompatible and is not inferred from one node seeing zero rows. |
| `TRSTCTL_SECRET_ROTATION_HISTORY_FLEET_READY` | `false` | Operator assertion that every older process able to read, export, or write schema-v1 `secret.rotation_schedule.ran` events is stopped. When retained unsafe error details exist, startup stays unready until this is true; it then performs the signed, deterministic live-generation sanitation and installs the v1 write floor. This is a one-way fleet compatibility decision, not a per-pod readiness guess. |
| `TRSTCTL_SECRETS_ENABLE_API` | `false` | Enables the served `/api/v1/secrets/*` surface, including store, dynamic leases, sharing, CSR-first PKI secret signing, deprecated auditable PKI keypair generation, machine login, sync, and Gitleaks scans. It also enables the Vault/OpenBao-compatible common aliases under `/v1/auth/token/lookup-self`, `/v1/secret/data/*`, `/v1/pki/sign/*`, and `/v1/pki/issue/*`. |
| `TRSTCTL_SECRETS_AUTH_SECRET_FILE` | unset | Optional HMAC key file for the builtin machine-login token verifier. Setting it also requires the tenant pin and explicit scopes below. The login method otherwise fails closed while other secrets routes continue to work. |
| `TRSTCTL_SECRETS_AUTH_TOKEN_TENANT_ID` | unset | Exact tenant UUID allowed to use the builtin HMAC token authority. One deployment-wide verifier is never implicitly trusted across tenants. Required with `TRSTCTL_SECRETS_AUTH_SECRET_FILE`. |
| `TRSTCTL_SECRETS_AUTH_TOKEN_SCOPES` | unset | Comma-separated least-privilege API permissions returned by the builtin token exchange, for example `secrets:read`. Required and non-empty with `TRSTCTL_SECRETS_AUTH_SECRET_FILE`; there is no implicit wildcard or inert empty grant. |
| `TRSTCTL_SECRETS_GITLEAKS_BIN` | auto-detect | Path to the pinned Gitleaks `v8.27.2` binary used by `POST /api/v1/secrets/scans`. Empty resolves `TRSTCTL_GITLEAKS_BIN`, `tools/bin/gitleaks`, then `PATH`. Run `tools/gitleaks/install.sh` during image build or host provisioning to install the supported checksum-verified release tarball. A missing binary makes scan requests fail closed with `503`. |

Every default-binary idempotency result is outer-sealed through the same
tenant-aware crypto resolver before PostgreSQL retains it. A legacy tenant uses
the deployment KEK explicitly. An opted-in tenant names exactly one separately
provisioned wrapper and never trial-decrypts or falls back to the deployment KEK.
The local wrapper file is opened only inside a tenant-scoped shared database
fence; its domain key lives in locked memory for that callback and is then wiped.
Before the HTTP mutation surface becomes ready, startup drains historical
`raw-v0` and `sealed-dynamic-lease-v1` cache rows in key-ordered, RLS-scoped
batches into the authenticated `sealed-row-v1` envelope. Each replacement is a
compare-and-swap over tenant, key, binding, codec, and prior bytes. A crash
therefore resumes safely, while a changed row or unavailable tenant wrapper
fails readiness without logging or embedding the result bytes in the error.
The runtime reader rejects both legacy codecs after this drain. When the
fleet-ready assertion is set, startup also locks the table, proves every
completed row is a CSL sealed container, changes the database default, and
validates a permanent sealed-only constraint before readiness. This is a
one-way compatibility decision: drain or stop all old writers first.

Schema-v1 scheduled-rotation terminal events from older releases could retain an
arbitrary provider error string. A current binary scans the complete retained
history before projection catch-up, audit search/retention, or backup export. If
unsafe bytes exist and the fleet assertion above is false, startup fails with one
fixed sanitation-required error. After the old fleet is stopped and the assertion
is true, startup switches to a signed replacement generation that changes only the
JSON `error` token to the status-specific closed vocabulary. Every other stored
envelope byte and sequence stays fixed; normal append/import then rejects v1
scheduler runs permanently. The operation does not and cannot rewrite backup,
export, or WORM/archive copies made before the switch.

```json
{
  "secrets": {
    "kek_file": "/run/secrets/deployment-kek",
    "tenant_seal_local_wrappers": [
      {"id": "operator-a", "file": "/run/custody/operator-a-wrapper"},
      {"id": "operator-b", "file": "/run/custody/operator-b-wrapper"}
    ]
  }
}
```

Wrapper files are operator authority, not ordinary application data. Provision
them separately with restrictive ownership/mode before configuring a tenant.
Missing, corrupt, or mismatched custody fails that tenant closed while other
tenants continue. This local mode makes no outbound call and works air-gapped.

Dynamic-secret providers and outbound sync targets use structured JSON/YAML because
each entry is bound to exactly one tenant. Authority-bearing values are references,
not inline strings: `file:/absolute/path` loads an operator-owned `0600` file, while
`secret://path` opens that tenant's encrypted secret-store row for one outbox attempt.
Both are copied into locked, non-dumpable memory and destroyed after the provider call.

```json
{
  "secrets": {"enable_api": true},
  "secret_integrations": {
    "dynamic_providers": [{
      "tenant_id": "11111111-1111-4111-8111-111111111111",
      "id": "orders-postgres",
      "type": "postgresql",
      "admin_dsn_ref": "file:/run/secrets/orders-postgres-admin-dsn",
      "database": "orders",
      "schema": "public",
      "allowed_roles": ["reader"],
      "max_ttl": "1h",
      "username_prefix": "trstctl_orders"
    }],
    "sync_targets": [{
      "tenant_id": "11111111-1111-4111-8111-111111111111",
      "id": "orders-github",
      "type": "github-actions",
      "endpoint": "https://api.github.com",
      "owner": "example",
      "repo": "orders",
      "token_ref": "secret://integrations/github-actions-token"
    }]
  }
}
```

Dynamic `type` values are `postgresql`, `mysql`, `mongodb`, `aws-iam`, `gcp-iam`,
`azure-entra`, `kubernetes`, and `redis`. Sync `type` values are
`aws-secrets-manager`, `gcp-secret-manager`, `azure-key-vault`, `github-actions`,
`gitlab-ci`, `vercel`, `generic-ci-json`, `kubernetes-secrets`,
`terraform-cloud-opentofu`, and `vault-kv-v2`. Startup validates each provider's
required native fields, role bindings, endpoint scheme, private-egress CIDRs, and
credential-reference form before accepting traffic. An absent tenant target or
provider fails its served mutation closed; it never falls back to another tenant or
to a test registry.

AWS, GCP, and Azure sync targets can explicitly replace their static target
credential with tenant-owned workload identity. Set exactly the provider switch
(`aws_workload_identity`, `gcp_workload_identity`, or
`azure_workload_identity`) on the matching target. The switch is false by default
and forbids the corresponding static credential fields when true. The workload
proof itself stays behind a `file:` or tenant-scoped `secret://` reference.
Only the bounded secret-sync outbox worker opens and validates that proof, POSTs the
provider exchange, caches the locked short-lived token until its refresh boundary,
and feeds it into the existing hand-written target client. The request handler never
performs that egress. Air-gapped mode records `offline_disabled`, fails that queued
delivery once, and makes no token or target request.

Azure uses an Entra federated credential that accepts the already validated OIDC
proof directly as the OAuth `client_assertion`. This is simpler than a
certificate-signed assertion: it adds no private key or certificate custody. Create
the matching federated-credential binding on the Entra application, then configure
the Key Vault target:

```yaml
secret_integrations:
  sync_targets:
    - tenant_id: 11111111-1111-4111-8111-111111111111
      id: payments-azure-key-vault
      type: azure-key-vault
      endpoint: https://payments.vault.azure.net
      azure_workload_identity: true
      # Optional. When omitted, the source's azure_tenant_id selects:
      # https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
      # workload_identity_endpoint: https://login.microsoftonline.com/.../oauth2/v2.0/token
```

Create the tenant-scoped source through the console or
`trstctl-cli secrets syncs workload-identities create --body-file source.json`.
For Azure, the request sets `provider: "azure"`, `azure_tenant_id`, the Entra
application `client_id`, and an allowed Key Vault `target_scope` such as
`https://vault.azure.net/.default`. It also binds the exact OIDC `audience` and
`subject`, `target_id`, allowed remote-key prefixes, `workload_proof_ref`, and a
JWT/JWKS `trust_source_id`. Those routing fields are stored under PostgreSQL RLS;
proof bytes and minted bearer tokens are never stored in the source row, event, job,
or API response.

Every dynamic-provider and sync-target HTTP endpoint must use HTTPS in production.
`allow_private_endpoint` grants a named private destination; it never grants plaintext.
Local emulators may set `allow_insecure_loopback: true`, but only beside an `http://`
endpoint whose host is exactly `localhost`, an address in `127.0.0.0/8`, or `::1`.
The runtime client resolves and dials loopback only, so changing DNS or adding a private
CIDR cannot stretch this development switch to a LAN, VPC, metadata service, or public
host.

Machine-auth methods beyond the HMAC token are configured in the JSON/YAML config
file under `secrets.machine_auth`. Each entry names one method: `kubernetes`,
`aws-iam`, `gcp`, `azure`, `oidc`, or `jwt`. JWT-family methods require
`audience` plus `jwks_file` or `jwks_json`, and must set either `tenant_claim`
(credential-bound tenancy) or `tenant_id` (tenant-pinned config). AWS IAM must set
`tenant_id` and `allowed_accounts` or `allowed_arns` because STS does not carry a
trstctl tenant claim. Every method must also choose exactly one permission source:
non-empty static `scopes`, or—for OIDC/generic JWT only—one signed
`scopes_claim`. Static scopes cannot be widened by a credential's generic `scope`
or `scopes` claim. Empty, duplicate, missing, or ambiguous scope configuration
fails startup instead of producing an inert or over-privileged session.

Treat the credential-store KEK as the root that also protects the signer's sealed
audit-evidence handle: **protect it and back it up** (a lost KEK means sealed
credentials and software-backed signer keys cannot be opened) with the same care
described in the [disaster-recovery runbook](disaster-recovery.md). This
credential-store KEK is still a local key file. Do not confuse it with Helm
`externalKMS`, which applies to the signer's CA key-store DEK wrapping described in
[Signer topology and CA custody](#signer-topology-and-ca-custody).
On reload, local KEK, auth-secret, and session-secret files are accepted only if
they are regular files, not symlinks, owned by the process user with
`0600`-or-stricter permissions or mounted as root-owned Kubernetes Secret files
readable by the pod's `fsGroup`, and all parent directories reject group/world
writes. Unsafe restored files fail startup instead of silently weakening key
custody.

## Backup

Event-log backups (`trstctl --backup`) are always integrity-protected (a SHA-256
trailer, plus an HMAC domain-derived from `TRSTCTL_SECRETS_KEK_FILE` when the
deployment KEK exists). They require the live deployment's external PostgreSQL DSN as well
as external NATS: PostgreSQL holds a shared history-generation barrier for the
complete export, preventing a concurrent privacy rewrite from changing which
JetStream generation is authoritative mid-backup. A **full** backup
(`trstctl --full-backup-dir`) additionally captures operational secrets — the
signer authorization secret and the sealed signer key store (including the
audit-evidence key) — so
production full backups require an operator-held encryption key.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_BACKUP_ENCRYPTION_KEY_FILE` | unset | Raw key-material file (normally 32 random bytes, never itself copied into the backup) used to AES-256-GCM-encrypt every sensitive full-backup artifact. Required for `--full-backup-dir` unless the override below is set. |
| `TRSTCTL_BACKUP_ALLOW_UNENCRYPTED` | `false` | Break-glass override that permits an unencrypted full backup for a lab/export case. The choice is recorded in the backup manifest so an auditor can see the locked box was not used. |
| `TRSTCTL_BACKUP_DIRECTORY` | unset | Full-backup directory the served integrity check and scheduled full-set restore drill read. Empty means the control plane reports backup automation as externally managed. |
| `TRSTCTL_BACKUP_DRILL_INTERVAL` | `24h` | Scheduled full restore cadence. `0` explicitly disables scheduling; malformed durations fail startup. Equivalent config key: `backup.drill_interval`. |
| `TRSTCTL_BACKUP_DRILL_RPO` | `24h` | Largest measured backup age accepted without an objective-breach alert. Equivalent config key: `backup.drill_rpo`. |
| `TRSTCTL_BACKUP_DRILL_RTO` | `1h` | Largest isolated-target restore duration accepted without an objective-breach alert. This is a floor for a real incident, not an RTO promise. Equivalent config key: `backup.drill_rto`. |

See the [disaster-recovery runbook](disaster-recovery.md) for the full backup/restore
procedure, including what each artifact covers and how to restore a signer host.
Every scheduled result is signed by the isolated `audit-export` signer handle,
appended to tenant-isolated history, and available through
`trstctl platform dr-posture`. Failed, skipped, and objective-breaching results
create an idempotent `notification.restore_drill` intent in the same PostgreSQL
transaction as that history row.

## License

trstctl ships as a single open-core binary. Enterprise-tier features (managed keys,
PCAS, HA support, FIPS artifact posture, remediation, PQC, governance, agent
delegation, reconciliation, and verifiable decommission — the full Enterprise row in
[Editions](editions.md)) unlock through an offline, no-phone-home license check: the
file is verified locally against public keys baked into the binary at release time.
No configured file means Community edition; a corrupt or untrusted file fails startup
loudly; an expired file still loads and walks a grace ladder so licensed read paths
stay observable.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_LICENSE_FILE` | unset (Community edition) | Path to the signed license file (Ed25519-verified offline, the AN-9 attach seam). |
| `TRSTCTL_LICENSE_DEPLOYMENT_ID` | unset | Stable runtime deployment ID. Required with `TRSTCTL_LICENSE_ENVIRONMENT` for a version 2 license; it must match the signed production ID or one of at most three signed non-production IDs. |
| `TRSTCTL_LICENSE_ENVIRONMENT` | unset | `production` or `non_production`. Required with `TRSTCTL_LICENSE_DEPLOYMENT_ID` for a version 2 license. A v1 compatibility license may omit both but remains production-only. |

The ID is not a secret and does not phone home. It is a local name bound by the
vendor's Ed25519 signature. Copying a non-production license to another control
plane without giving that deployment its own signed ID fails startup. See
[Editions](editions.md#signed-deployment-environment-entitlement) for the claim
shape and [Pricing](pricing.md#bundled-non-production-entitlement) for what is
included.

The related `TRSTCTL_PCAS_*` variable surface (about two dozen settings covering
delegation, recovery, federation, KEM, checkpoints, monitors, and retirement for
patent-covered credential algorithm succession) is off by default and gated by this
same license check; it is documented together with the rest of the PCAS material in
[PCAS operations](runbooks/pcas-operations.md) rather than duplicated here.

## Conditional managed-key adapters (six served providers)

The managed-key lifecycle is off by default and requires an Enterprise license plus
startup configuration. AWS KMS, Azure Key Vault / Managed HSM, GCP Cloud KMS,
PKCS#11, TPM 2.0, and YubiHSM 2 are all required/census-served through the shipped
cgo HSM signer artifact. “Conditional” means the route is inert until the operator
selects and provisions one provider; it no longer means library-only. The control
plane records a tenant event and PostgreSQL outbox command, while the isolated signer
constructs the provider and performs the private operation. The control-plane process
never receives provider credentials.

The **Certificate authorities → Key custody** console reads
`GET /api/v1/managed-keys/custody` to show this startup configuration as a secret-free
plan. It names environment variables and signer-only file-reference requirements for
all six providers; it does not accept their values. After startup configuration is
applied and the control plane and isolated signer are restarted, the console calls
`POST /api/v1/managed-keys/preview`. That request is effect-free: it writes no event or
projection and makes no provider call. Generation stays locked until the preview
confirms the selected provider matches the running provider, the lifecycle is
attached, and the exact plan is ready.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_MANAGED_KEYS_ENABLED` | `false` | Enables licensed managed-key event/outbox assembly. When false, the routes fail closed; no provider is constructed. |
| `TRSTCTL_MANAGED_KEYS_PROVIDER` | `aws` | Custody provider: `aws`, `azure-key-vault`, `gcp-kms`, `pkcs11`, `tpm2`, or `yubihsm2`. Selection is startup-static ordinary interface injection, not a runtime plugin engine. |
| `TRSTCTL_MANAGED_KEYS_AWS_REGION` | unset | AWS region for KMS, for example `us-east-1`. Required when enabled. |
| `TRSTCTL_MANAGED_KEYS_AWS_ENDPOINT` | unset | Optional absolute HTTPS endpoint override, used for VPC endpoints or partitions. Leave unset for regional AWS KMS. |
| `TRSTCTL_MANAGED_KEYS_AWS_ALLOW_INSECURE_LOOPBACK` | `false` | Development-only plaintext opt-in. It is accepted only when the AWS endpoint is `http://localhost`, `http://127.0.0.0/8`, or `http://[::1]`; resolved non-loopback addresses still fail at dial time. |
| `TRSTCTL_MANAGED_KEYS_AWS_ACCESS_KEY_ID` | unset | AWS access key id. Required for the current served AWS KMS backend. |
| `TRSTCTL_MANAGED_KEYS_AWS_SECRET_ACCESS_KEY` | unset | Inline compatibility input. The isolated child-signer path rejects it; use the file variant. |
| `TRSTCTL_MANAGED_KEYS_AWS_SECRET_ACCESS_KEY_FILE` | unset | File containing the AWS secret access key. Startup reads it, constructs the backend, and wipes the temporary file buffer. |
| `TRSTCTL_MANAGED_KEYS_AWS_SESSION_TOKEN` | unset | Inline compatibility input. The isolated child-signer path rejects it; use the optional file variant. |
| `TRSTCTL_MANAGED_KEYS_AWS_SESSION_TOKEN_FILE` | unset | Optional file containing the temporary session token. |
| `TRSTCTL_MANAGED_KEYS_AWS_PRIVATE_EGRESS_CIDRS` | unset | Comma-separated private CIDRs explicitly granted to an AWS private/VPC endpoint. Metadata and link-local destinations remain blocked. |
| `TRSTCTL_MANAGED_KEYS_AZURE_VAULT_URL` | unset | Azure Key Vault or Managed HSM vault URL, for example `https://trstctl-prod.managedhsm.azure.net`. Required when provider is `azure-key-vault`. |
| `TRSTCTL_MANAGED_KEYS_AZURE_ENDPOINT` | unset | Optional absolute HTTPS endpoint override for private endpoints. Leave unset for the vault URL. |
| `TRSTCTL_MANAGED_KEYS_AZURE_ALLOW_INSECURE_LOOPBACK` | `false` | Development-only plaintext opt-in restricted to a loopback `vault_url` or endpoint; it cannot authorize private-network or public HTTP. |
| `TRSTCTL_MANAGED_KEYS_AZURE_BEARER_TOKEN` | unset | Inline compatibility input. The isolated child-signer path rejects it; use the file variant. |
| `TRSTCTL_MANAGED_KEYS_AZURE_BEARER_TOKEN_FILE` | unset | File containing the Azure bearer token. Startup reads it, constructs the backend, and wipes the temporary file buffer. |
| `TRSTCTL_MANAGED_KEYS_AZURE_PRIVATE_EGRESS_CIDRS` | unset | Comma-separated private CIDRs explicitly granted to an Azure private endpoint. Metadata and link-local destinations remain blocked. |
| `TRSTCTL_MANAGED_KEYS_GCP_PARENT` | unset | GCP Cloud KMS key-ring resource, for example `projects/P/locations/L/keyRings/R`. Required when provider is `gcp-kms`. |
| `TRSTCTL_MANAGED_KEYS_GCP_ENDPOINT` | unset | Optional absolute HTTPS endpoint override for private service endpoints. Leave unset for `https://cloudkms.googleapis.com/v1`. |
| `TRSTCTL_MANAGED_KEYS_GCP_ALLOW_INSECURE_LOOPBACK` | `false` | Development-only plaintext opt-in restricted to an HTTP loopback endpoint; it cannot authorize private-network or public HTTP. |
| `TRSTCTL_MANAGED_KEYS_GCP_BEARER_TOKEN` | unset | Inline compatibility input. The isolated child-signer path rejects it; use the file variant. |
| `TRSTCTL_MANAGED_KEYS_GCP_BEARER_TOKEN_FILE` | unset | File containing the GCP bearer token. Startup reads it, constructs the backend, and wipes the temporary file buffer. |
| `TRSTCTL_MANAGED_KEYS_GCP_PRIVATE_EGRESS_CIDRS` | unset | Comma-separated private CIDRs explicitly granted to a GCP private service endpoint. Metadata and link-local destinations remain blocked. |
| `TRSTCTL_MANAGED_KEYS_PKCS11_MODULE_PATH` | unset | Native PKCS#11 module path, for example `libsofthsm2.so`, nShield `cknfast`, or Luna `Cryptoki`. Required when provider is `pkcs11`. |
| `TRSTCTL_MANAGED_KEYS_PKCS11_TOKEN_LABEL` | unset | Initialized token label to log in to. Required when provider is `pkcs11`. |
| `TRSTCTL_MANAGED_KEYS_PKCS11_USER_PIN` | unset | Inline compatibility input. The isolated child-signer path rejects it; use the file variant. |
| `TRSTCTL_MANAGED_KEYS_PKCS11_USER_PIN_FILE` | unset | File containing the PKCS#11 user PIN. Startup reads it, constructs the backend, and wipes the temporary file buffer. |
| `TRSTCTL_MANAGED_KEYS_PKCS11_KEY_LABEL_PREFIX` | `trstctl-pkcs11` | Label prefix for generated token objects. |
| `TRSTCTL_MANAGED_KEYS_TPM2_PATH` | unset | Linux TPM device (for example `/dev/tpmrm0`) or swtpm Unix socket. Required for `tpm2`. |
| `TRSTCTL_MANAGED_KEYS_TPM2_OWNER_AUTH` | unset | Inline compatibility input. The isolated child-signer path rejects it; use `OWNER_AUTH_FILE` when hierarchy auth is required. |
| `TRSTCTL_MANAGED_KEYS_TPM2_OWNER_AUTH_FILE` | unset | Optional file containing TPM owner-hierarchy authorization. |
| `TRSTCTL_MANAGED_KEYS_TPM2_KEY_AUTH` | unset | Inline compatibility input. The isolated child-signer path rejects it; use `KEY_AUTH_FILE`. |
| `TRSTCTL_MANAGED_KEYS_TPM2_KEY_AUTH_FILE` | unset | Optional file containing authorization assigned to generated signing objects. |
| `TRSTCTL_MANAGED_KEYS_TPM2_PERSISTENT_HANDLE_BASE` | `0x81010000` | First signer-owned persistent handle. The first 256 handles remain the legacy fresh-key bank; operation-aware keys deterministically probe the remaining persistent range and carry the full durable-operation digest in immutable `TPM Public.AuthPolicy`. Foreign occupied handles are skipped, never adopted or overwritten. |
| `TRSTCTL_MANAGED_KEYS_YUBIHSM2_MODULE_PATH` | unset | Path to Yubico's `yubihsm_pkcs11` module. Required for `yubihsm2`. |
| `TRSTCTL_MANAGED_KEYS_YUBIHSM2_TOKEN_LABEL` | unset | Token/connector label selected through the vendor PKCS#11 ABI. |
| `TRSTCTL_MANAGED_KEYS_YUBIHSM2_USER_PIN` | unset | Inline compatibility input. The isolated child-signer path rejects it; use the file variant. |
| `TRSTCTL_MANAGED_KEYS_YUBIHSM2_USER_PIN_FILE` | unset | File containing the YubiHSM authentication value/PIN. |
| `TRSTCTL_MANAGED_KEYS_YUBIHSM2_KEY_LABEL_PREFIX` | `trstctl-pkcs11` | Label prefix for generated YubiHSM signing objects. |

| Provider | Shipped binding | Required proof substrate |
| --- | --- | --- |
| `aws` | AWS SDK v2 asymmetric KMS | Faithful SigV4 KMS emulator |
| `azure-key-vault` | Azure Keys/Managed HSM data plane | Faithful Managed HSM wire emulator |
| `gcp-kms` | GCP Cloud KMS REST data plane | Faithful resource/digest emulator |
| `pkcs11` | Native cgo PKCS#11 module | SoftHSM plus independent `pkcs11-tool` readback |
| `tpm2` | `google/go-tpm` persistent object driver | swtpm plus independent `tpm2-tools` readback |
| `yubihsm2` | Yubico PKCS#11 connector ABI | SoftHSM-backed vendor-ABI emulator |

Development-only LocalStack shape (not conformance or shipped-runtime proof):

```bash
export TRSTCTL_MANAGED_KEYS_ENABLED=true
export TRSTCTL_MANAGED_KEYS_PROVIDER=aws
export TRSTCTL_MANAGED_KEYS_AWS_REGION=us-east-1
export TRSTCTL_MANAGED_KEYS_AWS_ENDPOINT=http://127.0.0.1:4566
export TRSTCTL_MANAGED_KEYS_AWS_ALLOW_INSECURE_LOOPBACK=true
export TRSTCTL_MANAGED_KEYS_AWS_ACCESS_KEY_ID=test
printf '%s' test > /tmp/localstack-kms-secret
chmod 0600 /tmp/localstack-kms-secret
export TRSTCTL_MANAGED_KEYS_AWS_SECRET_ACCESS_KEY_FILE=/tmp/localstack-kms-secret
```

Private endpoint CIDR grants control *where* HTTPS may go. They never weaken TLS.
The three `ALLOW_INSECURE_LOOPBACK` switches are deliberately separate and accept
only loopback HTTP for a same-host emulator.

Example production shape:

```yaml
managed_keys:
  enabled: true
  provider: aws
  aws:
    region: us-east-1
    access_key_id: AKIA...
    secret_access_key_file: /etc/trstctl/aws-kms-secret-access-key
```

Example Azure Key Vault HSM shape:

```yaml
managed_keys:
  enabled: true
  provider: azure-key-vault
  azure:
    vault_url: https://trstctl-prod.managedhsm.azure.net
    bearer_token_file: /etc/trstctl/azure-kv-token
```

Example GCP Cloud KMS shape:

```yaml
managed_keys:
  enabled: true
  provider: gcp-kms
  gcp:
    parent: projects/prod/locations/us/keyRings/trstctl
    bearer_token_file: /etc/trstctl/gcp-kms-token
```

Example PKCS#11 HSM shape:

```yaml
managed_keys:
  enabled: true
  provider: pkcs11
  pkcs11:
    module_path: /usr/lib/softhsm/libsofthsm2.so
    token_label: trstctl-prod
    user_pin_file: /etc/trstctl/pkcs11-user-pin
    key_label_prefix: trstctl-ca
```

Example TPM 2.0 shape:

```yaml
managed_keys:
  enabled: true
  provider: tpm2
  tpm2:
    path: /dev/tpmrm0
    owner_auth_file: /etc/trstctl/tpm-owner-auth
    key_auth_file: /etc/trstctl/tpm-key-auth
    persistent_handle_base: 2164326400 # 0x81010000
```

Example YubiHSM 2 shape:

```yaml
managed_keys:
  enabled: true
  provider: yubihsm2
  yubihsm2:
    module_path: /usr/lib/yubihsm_pkcs11.so
    token_label: trstctl-prod
    user_pin_file: /etc/trstctl/yubihsm-auth
    key_label_prefix: trstctl-ca
```

Static no-cgo signer builds fail closed if `pkcs11` or `yubihsm2` is selected.
Use the published artifact built by `deploy/docker/Dockerfile.signer-hsm`; its
release profile enables cgo and installs `/usr/local/bin/trstctl-signer-hsm`.

When the licensed attach seam succeeds, operators with `keys:write` can exercise
`POST /api/v1/managed-keys` and the rotate/revoke/zeroize API and CLI shapes. Before
each destructive action, two different principals with `keys:approve` record the
exact opaque `key_id` and `rotate`, `revoke`, or `zeroize` action through
`POST /api/v1/managed-keys/approvals`; the requester cannot self-approve. Requests
require `Idempotency-Key`; lifecycle events omit private bytes; tenant projections
use PostgreSQL RLS; and provider work is delivered by the durable outbox to the
separate signer. The signer writes an fsync-backed operation intent before provider I/O.
Every shipped provider also carries that identity into provider state: an atomic AWS tag,
deterministic Azure/GCP resource identity, deterministic PKCS#11 `CKA_ID` (including
YubiHSM), or a full-width TPM public tag plus deterministic handle probing. If a provider
commits and the signer dies before journaling the response, restart finds the same effect;
revoke/zeroize likewise confirm terminal provider state rather than blindly repeating a
mutation. Managed-key outbox circuits are partitioned by provider and current key (or
operation ID before a key exists), so one unavailable key does not stall every managed-key
command. All six exact backend census rows are `SERVED + REQUIRED`.
For an externally deployed signer, mount the same file-backed provider descriptor
and pass it with `--managed-keys-config` plus the signed `--license`; never copy a
credential into argv or an inline JSON field.

## Signer topology and CA custody

The private-key operations run in a separate, sacred process, so the CA keys never
live in the API process. Its issuing **CA key is persisted, sealed at rest** (R3.2)
so a restart preserves the CA instead of silently rotating it. The signer can run
two ways:

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_SIGNER_MODE` | `child` | `child`: the control plane supervises `trstctl-signer` as a child process (single binary). `external`: it connects to a **separately deployed** signer service over a UDS (`TRSTCTL_SIGNER_SOCKET`) or, across nodes, mTLS (`TRSTCTL_SIGNER_MTLS_ADDRESS`). |
| `TRSTCTL_SIGNER_SOCKET` | — | The signer's Unix-domain socket. In `external` mode set **either** this **or** `TRSTCTL_SIGNER_MTLS_ADDRESS`; in `child` mode a temp socket is used if unset. |
| `TRSTCTL_SIGNER_CALL_TIMEOUT` | `10s` | Bounds every signer RPC that lacks a tighter caller deadline (OPS-TIMEOUTS-001), so a hung signer fails closed instead of stalling issuance. Accepts `1s`..`2m`. |
| `TRSTCTL_SIGNER_KEY_STORE_DIR` | `data/signer/keys` | Directory where the signer **seals its keys at rest** (child mode passes it to the signer; in external mode set it on the signer service). |
| `TRSTCTL_SIGNER_AUTH_SECRET_FILE` | `data/signer/sign-auth.bin` | Signer-side content-authorization verifier secret. The signer uses it to verify dual-control tokens before using privileged handles. Do not mount it into the control plane in production. |
| `TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND` | — | Independent approval-token command used by the control plane in production. The command receives sign-intent JSON on stdin and returns the raw token as base64 on stdout. |
| `TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER` | `true` in single-node eval defaults | Evaluation-only escape hatch that lets the control plane mint signer tokens from `TRSTCTL_SIGNER_AUTH_SECRET_FILE`. Production-like external NATS deployments reject it; use `TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND` instead. |
| `TRSTCTL_SIGNER_ALLOW_INSECURE_DEV_NONLINUX` | `false` | Local-development-only escape hatch for running child signer mode on non-Linux hosts. Without it, `trstctl-signer` refuses startup when process hardening, UDS peer UID checks, and locked memory are unavailable. Do not set it in production. |
| `TRSTCTL_SIGNER_MTLS_ADDRESS` | — | `host:port` of a separately-hosted signer's **mTLS** listener. When set (in `external` mode), the control plane reaches the signer over TLS 1.3 mutual auth with **both-ways certificate pinning** instead of a UDS. Mutually exclusive with `TRSTCTL_SIGNER_SOCKET`. |
| `TRSTCTL_SIGNER_MTLS_SERVER_NAME` | — | The signer certificate's expected SAN, verified by the control plane. **Required** when `TRSTCTL_SIGNER_MTLS_ADDRESS` is set. |
| `TRSTCTL_SIGNER_MTLS_CERT_FILE` / `TRSTCTL_SIGNER_MTLS_KEY_FILE` | — | The control plane's own **client** certificate and key (PEM) presented on the mTLS channel. Required with `…_MTLS_ADDRESS`. |
| `TRSTCTL_SIGNER_MTLS_PEER_CA_FILE` | — | PEM CA bundle anchoring the **signer's** certificate. Required with `…_MTLS_ADDRESS`. |
| `TRSTCTL_SIGNER_MTLS_PEER_PIN` | — | Hex SHA-256 of the **signer** certificate's public key, pinned by the control plane. Required with `…_MTLS_ADDRESS`. |
| `TRSTCTL_CA_CERT_FILE` | `data/ca/issuing-ca.crt` | Where the issuing CA's self-signed certificate is persisted, so the control plane **reuses the same CA cert** across restarts. |
| `TRSTCTL_CA_PUBLIC_CERT_FILE` | — | Optional certificate-only mirror of the issuing CA. Use this to give an unprivileged bootstrap client the public trust anchor without mounting the private control-plane data volume. The control plane republishes it from `TRSTCTL_CA_CERT_FILE` on every successful CA bind. |

In Helm deployments, the signer key store uses local KEK custody by default:
`kek.existingSecret` or eval-only `kek.generate=true` mounts
`/etc/trstctl/kek/kek.bin` and the chart passes `--kek` to `trstctl-signer`.
Regulated deployments can instead set:

```yaml
externalKMS:
  enabled: true
  provider: awskms        # awskms | gcpkms | azurekv | pkcs11
  keyRef: arn:aws:kms:us-east-1:111122223333:key/trstctl-signer
  wrapCommand: /usr/local/bin/trstctl-kms-wrap
  timeout: 10s
```

With `externalKMS.enabled=true`, the chart passes `--kms-provider`,
`--kms-key-ref`, `--kms-wrap-command`, and `--kms-timeout` to the signer and does
not mount the local KEK Secret. The signer invokes the adapter without a shell as
`<wrapCommand> wrap|unwrap <provider> <keyRef>`, with DEK bytes only on
stdin/stdout. Missing provider/keyRef/command values, unsupported provider names,
or a relative command path fail at template time.

Back up the sealed key store, the signer custody input, and the CA cert together
(the CA-key recovery set) per the [disaster-recovery runbook](disaster-recovery.md).
For local-KEK mode that custody input is the signer KEK Secret; for externalKMS
mode it is access to the same provider keyRef plus the wrapper adapter and provider
credentials. The
`deploy/docker/docker-compose.yml` in the source checkout
runs the signer as its **own service** in `external` mode.

## Regulated CA governance mode

The individual issuance controls — the OPA/Rego policy gate, four-eyes dual
control, a bound default certificate profile, revocation publication, and FIPS — can
each be enabled on their own. For a compliance deployment that is error-prone: a
single missing control silently weakens the posture. `ca.governance_mode=regulated`
is the **one coherent switch** that closes that gap. In regulated mode the binary
**fails startup** unless **all** of these are present together, each with an
actionable error naming the field to set:

- the **OPA policy gate** is on (`ca.policy.enabled=true`);
- **four-eyes dual control** is on (`ca.policy.require_approval=true`) with at least
  **two** distinct approvers (`ca.policy.required_approvals` unset, defaulting to 2,
  or `>= 2`) — a single approver is rejected;
- a **default certificate profile** is bound (`ca.default_profile`);
- **revocation publication** is configured — at least one of
  `ca.crl_distribution_points` or `ca.ocsp_servers` — so issued leaves carry a
  status pointer (composing with the served-leaf profile);
- and, when `ca.require_fips=true` is declared, the **FIPS 140-3 module is active**
  (the binary was built with `GOFIPS140=v1.0.0` / `make fips-build`, or run with
  `GODEBUG=fips140=on`).

A **complete** regulated config boots normally. The default posture
(`ca.governance_mode` unset, or `standard`) imposes no coupling, so existing
single-node deployments are unaffected.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_CA_GOVERNANCE_MODE` | `standard` | `standard` (or unset): the controls are independent. `regulated`: fail startup unless the policy gate, four-eyes dual control, a bound default profile, revocation publication, and any declared FIPS requirement are **all** present together. |
| `TRSTCTL_CA_REQUIRE_FIPS` | `false` | In `regulated` mode, additionally require the FIPS 140-3 module to be active (build with `GOFIPS140=v1.0.0` or run with `GODEBUG=fips140=on`); otherwise startup fails closed. Ignored outside regulated mode. |

## Served AI surface and model adapter

The AI/RCA/MCP surface is off by default. MCP investigation tools are read-only when
enabled; MCP write tools require the separate `TRSTCTL_AI_MCP_WRITE_TOOLS=true`
operator opt-in. The control plane serves the tools as authenticated REST routes
(`GET /api/v1/mcp/tools`, `POST /api/v1/mcp/tools/{tool}`); a standard Model Context
Protocol client connects through `trstctl-cli mcp serve`, which speaks the MCP stdio
transport (JSON-RPC 2.0: `initialize`, `tools/list`, `tools/call`) and forwards every
call to those routes with the caller's own token, so tenant scope, RBAC, rate limits
and audit apply unchanged. Verified with the official MCP SDK client. The model adapter is separately off by default: with
`TRSTCTL_AI_MODEL_MODE=off` (or unset), query/RCA still return grounded citations, but
no prompt leaves the process.
`GET /api/v1/ai/status` reports the live enabled state, model mode, endpoint host,
egress class, and redaction/refusal posture without echoing the full endpoint URL.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_AI_ENABLE_API` | `false` | Serve `/api/v1/ai/status`, `/api/v1/ai/query`, `/api/v1/ai/rca`, and `/api/v1/mcp/tools*` behind auth/RBAC. |
| `TRSTCTL_AI_MCP_IDENTITY` | — | Workload identity label the MCP server presents. |
| `TRSTCTL_AI_MCP_WRITE_TOOLS` | `false` | Expose guarded MCP write tools (`issue_certificate`, `rotate_certificate`). Calls still require `certs:issue`, an `Idempotency-Key`, and are audited as `mcp.tool.write`. |
| `TRSTCTL_AI_RATE_MAX` | `60` | Per-caller MCP tool-call budget per window. |
| `TRSTCTL_AI_RATE_WINDOW_SECONDS` | `60` | MCP tool-call rate window in seconds. |
| `TRSTCTL_AI_MODEL_MODE` | `off` | `off`, `local`, or `cloud`. `off` means no model adapter and no prompt egress. |
| `TRSTCTL_AI_MODEL_RUNTIME` | — | Local runtime label, required with `mode=local`: `ollama` or `vllm`. |
| `TRSTCTL_AI_MODEL_PROVIDER` | — | Cloud/gateway provider label, required with `mode=cloud`. |
| `TRSTCTL_AI_MODEL_ENDPOINT` | — | Completion endpoint. Local `http://` endpoints must be loopback; otherwise use HTTPS. Cloud endpoints must be HTTPS. URL userinfo is rejected so credentials are not stored in config. |
| `TRSTCTL_AI_MODEL_NAME` | — | Model name sent to the configured endpoint. Required with `mode=local` or `mode=cloud`. |
| `TRSTCTL_AI_MODEL_ALLOW_EGRESS` | `false` | Required as `true` with `mode=cloud`; invalid for `off` and `local`. |

Ollama local mode sends the native generate shape to the endpoint. vLLM and cloud
mode send an OpenAI-compatible chat-completions shape. Every model path goes
through the boundary redactor and residual-secret refusal gate before the HTTP
request is made; if no model is configured, the answer remains citation-grounded
and air-gapped.

## Served protocol listeners

ACME, EST, SCEP, CMP, SPIFFE, SSH, and KMIP protocol surfaces are opt-in until they are
explicitly bound to a tenant. That startup check is intentional: a public protocol
endpoint must know the tenant it acts for before it is exposed. KMIP is a raw mTLS TCP
listener, not an HTTP route, so it additionally requires server certificate/key files
and a client CA trust anchor.

For the blank evaluation stack, `TRSTCTL_PROTOCOLS_PROFILE=eval` is a bounded shortcut:
it assembles ACME, EST, SCEP, CMP, SSH, TSA, and SPIFFE for exactly
`TRSTCTL_PROTOCOLS_EVAL_TENANT_ID`. Those responders stay behind a closed runtime gate
until a tenant-authenticated operator activates them in the first-run wizard or with
`POST /api/v1/setup/protocols/activate`. Activation appends an immutable tenant event
before the HTTP routes and SPIFFE socket become reachable, and replay restores the gate
after restart. The shortcut never enables KMIP. Production can omit `PROFILE` and use
the individual toggles below.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_PROTOCOLS_PROFILE` | — | Set to `eval` only for the guided evaluation profile. Empty keeps the exact individual, default-off production toggles. |
| `TRSTCTL_PROTOCOLS_EVAL_TENANT_ID` | — | Required with `PROFILE=eval`; binds every eval responder and its activation event to one tenant. |
| `TRSTCTL_PROTOCOLS_EVAL_SPIFFE_TRUST_DOMAIN` | `eval.trstctl.local` | SPIFFE trust domain used by the eval profile. The explicit SPIFFE setting below remains the production control. |
| `TRSTCTL_PROTOCOLS_ACME_ENABLED` / `…_TENANT_ID` | `false` / — | Serve ACME at `/directory` + `/acme/...` for the named tenant. |
| `TRSTCTL_PROTOCOLS_ACME_EAB_REQUIRED` | `false` | Require RFC 8555 External Account Binding on ACME `newAccount`; `/directory` advertises `externalAccountRequired`. |
| `TRSTCTL_PROTOCOLS_ACME_EAB_KEY_ID` | — | Public EAB `kid` accepted by the ACME server. The single env shortcut configures one key; JSON config can carry multiple `protocols.acme_eab.keys`. |
| `TRSTCTL_PROTOCOLS_ACME_EAB_HMAC_KEY` / `…_FILE` | — | Byte-backed HS256 HMAC key for the EAB `kid`; use the file form for production secret injection. |

Each entry in `protocols.acme_eab.keys[]` also carries the scope that credential
authorizes — `allowed_identifiers` (exact names or `*.suffix`, which covers the apex
too), `max_orders`, an RFC 3339 `not_after`, and `disabled`. All are optional and a key
with none behaves as it did before. An order outside a credential's scope, past its
quota, or after its window is refused fail-closed and recorded. Scope has no env
shortcut: it is per-key structured config. See
[ACME external account bindings](features/acme-and-dns.md).

| `TRSTCTL_PROTOCOLS_ACME_MAX_NONCES` | `4096` | Maximum outstanding ACME replay nonces retained by the tenant-bound ACME mount. |
| `TRSTCTL_PROTOCOLS_ACME_MAX_ACCOUNTS` | `2048` | Maximum ACME accounts retained by the tenant-bound ACME mount. |
| `TRSTCTL_PROTOCOLS_ACME_MAX_PENDING_ORDERS` | `4096` | Maximum pending ACME orders retained before the server returns ACME `rateLimited` (429). |
| `TRSTCTL_PROTOCOLS_ACME_MAX_PENDING_AUTHORIZATIONS` | `8192` | Maximum pending ACME authorizations retained across pending orders. |
| `TRSTCTL_PROTOCOLS_ACME_MAX_PENDING_CHALLENGES` | `24576` | Maximum pending ACME challenge records retained across pending authorizations. |
| `TRSTCTL_PROTOCOLS_ACME_MAX_PENDING_ORDERS_PER_ACCOUNT` | `128` | Per-account pending-order cap, independent from source-IP budgets. |
| `TRSTCTL_PROTOCOLS_ACME_MAX_NEW_NONCES_PER_SOURCE` | `120` | Per-source newNonce budget per source window. |
| `TRSTCTL_PROTOCOLS_ACME_MAX_NEW_ACCOUNTS_PER_SOURCE` | `20` | Per-source account-creation budget per source window. |
| `TRSTCTL_PROTOCOLS_ACME_MAX_NEW_ORDERS_PER_SOURCE` | `60` | Per-source order-creation budget per source window. |
| `TRSTCTL_PROTOCOLS_ACME_SOURCE_WINDOW_SECONDS` | `600` | Source-budget window for ACME nonce/account/order creation. |
| `TRSTCTL_PROTOCOLS_ACME_NONCE_TTL_SECONDS` | `600` | TTL for unused ACME replay nonces before the request-time janitor drops them. |
| `TRSTCTL_PROTOCOLS_ACME_STATE_TTL_SECONDS` | `86400` | TTL for pending ACME order/authorization/challenge state before the request-time janitor drops it. |
| `TRSTCTL_PROTOCOLS_EST_ENABLED` / `…_TENANT_ID` | `false` / — | Serve EST at `/.well-known/est/...` for the named tenant. |
| `TRSTCTL_PROTOCOLS_SCEP_ENABLED` / `…_TENANT_ID` | `false` / — | Serve SCEP at `/scep` for the named tenant. |
| `TRSTCTL_PROTOCOLS_CMP_ENABLED` / `…_TENANT_ID` | `false` / — | Serve CMP at `/cmp` for the named tenant. |
| `TRSTCTL_PROTOCOLS_TSA_ENABLED` / `…_TENANT_ID` | `false` / — | Serve RFC 3161 timestamp evidence for the named tenant through the signer-held timestamping key, instead of minting inventory certificates. |
| `TRSTCTL_PROTOCOLS_RA_KEY_FILE` | `data/protocols/ra-transport.key` | Sealed SCEP/CMP RSA transport identity. Put this on shared persistent storage in HA so replicas use the same cached-client RA material. |
| `TRSTCTL_PROTOCOLS_TSA_CERT_FILE` | `data/protocols/tsa.crt` | Where the TSA's timestamping certificate is persisted, so it stays stable across restarts and is shared across HA replicas. Required when TSA is enabled. |
| `TRSTCTL_PROTOCOLS_KMIP_ENABLED` / `…_TENANT_ID` | `false` / — | Serve the KMIP mTLS listener for the named tenant. The current served profile supports AES-256 SymmetricKey Create/Get/Locate/Revoke/Destroy. |
| `TRSTCTL_PROTOCOLS_KMIP_ADDR` | `:5696` | TCP listen address for KMIP. |
| `TRSTCTL_PROTOCOLS_KMIP_CERT_FILE` | — | PEM server certificate chain for the KMIP listener. Required when KMIP is enabled. |
| `TRSTCTL_PROTOCOLS_KMIP_KEY_FILE` | — | PEM private key for the KMIP listener certificate. Required when KMIP is enabled. |
| `TRSTCTL_PROTOCOLS_KMIP_CLIENT_CA_FILE` | — | PEM CA bundle used to verify KMIP client certificates. Required when KMIP is enabled. |
| `TRSTCTL_PROTOCOLS_SPIFFE_ENABLED` / `…_TENANT_ID` | `false` / — | Serve the SPIFFE Workload API UDS for the named tenant. Requires `TRSTCTL_PROTOCOLS_SPIFFE_TRUST_DOMAIN`. |
| `TRSTCTL_PROTOCOLS_SPIFFE_SOCKET_PATH` | `/tmp/trstctl-spiffe-workload.sock` | UDS path for the SPIFFE Workload API when enabled. |
| `TRSTCTL_PROTOCOLS_SPIFFE_TRUST_DOMAIN` | — | SPIFFE trust domain, for example `example.org`. Required when SPIFFE is enabled. |
| `TRSTCTL_PROTOCOLS_SSH_ENABLED` / `…_TENANT_ID` | `false` / — | Serve the SSH CA JSON endpoints and KRL for the named tenant. |

## Agent mTLS channel

The served agent gRPC channel is a real listener the control plane exposes for
steady-state agent heartbeat, renewal, and command fan-out (WIRE-004 / OPS-005) —
separate from the one-shot bootstrap enrollment path, which always works. It is
**off by default**; enabling it without a configured signer (the agent CA is
custodied there) is a startup error.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_AGENT_CHANNEL_ENABLED` | `false` | Mounts the served agent mTLS gRPC channel on `TRSTCTL_AGENT_CHANNEL_ADDR`. Requires a configured signer. |
| `TRSTCTL_AGENT_CHANNEL_ADDR` | `:9443` | The agent channel's mTLS gRPC listen address. |
| `TRSTCTL_AGENT_CHANNEL_PUBLIC_ADDRESS` | empty | Exact externally reachable `host:port` the API returns with a one-time enrollment token and the console places in `--server`. This is intentionally separate from the listen address because Compose, Kubernetes Services, load balancers, and tunnels can remap the port. When empty, the console refuses to guess a runnable command. A non-loopback host also requires `TRSTCTL_AGENT_CHANNEL_SERVER_NAME`. |
| `TRSTCTL_AGENT_CHANNEL_HTTP_RENEWAL_ADDR` | `:9444` | Dedicated embedded-client HTTPS renewal listener. Served only when the channel is enabled, uses the same signer-custodied agent CA, and requires a verified agent client certificate. |
| `TRSTCTL_AGENT_CHANNEL_SERVER_NAME` | empty (loopback SANs only) | DNS SAN the channel's server certificate carries — the name agents pin/verify as their `--server-name`. Loopback SANs are always added so a co-located agent can verify a `localhost` connection. |
| `TRSTCTL_AGENT_CHANNEL_CA_CERT_FILE` | `data/ca/agent-ca.crt` | Where the agent CA certificate is persisted, so an agent's pinned signer key does not change on restart. The shipped container sets `WORKDIR /`, so this default resolves to the persistent `/data/ca/agent-ca.crt`; Compose and Helm also set that absolute path explicitly. |
| `TRSTCTL_AGENT_CHANNEL_HEARTBEAT_INTERVAL` | `30s` | Next-beat hint returned to agents. |
| `TRSTCTL_AGENT_CHANNEL_CLAIMABLE_JOB_KINDS` | empty | Comma-separated, explicit allowlist of estate-touching jobs agents may claim. Empty fails closed. |

**Which work agents may claim.** `agent_channel.claimable_job_kinds`, or its
comma-separated `TRSTCTL_AGENT_CHANNEL_CLAIMABLE_JOB_KINDS` environment form,
lists the estate-touching job kinds enrolled agents may lease and execute:
`connector.deploy`, `connector.test`, `connector.rollback`, `endpoint.renew`,
`endpoint.verify`, `discovery.run`, `revocation.probe`, `adcs.inventory`,
`trust.distribute`, `cmdb.sync`, `mdm.sync`, `ticket.sync`, and `agent.upgrade`.

Empty is the default and means the job ledger is served but hands nothing out.
Enable a kind when its agent-side executor ships; enabling one earlier fills the
queue with work nothing can perform while the control plane's own worker stops
doing it. Anything outside that list is dropped even if you write it here, so
`ca.issue` and `notification.expiry` cannot be moved onto a host — those are the
control plane's own effects. `GET /api/v1/operations/jobs` and the Operations
console show what is waiting, what an agent holds, and how long the oldest job has
waited.

The evaluation Compose stack enables only `discovery.run`, `endpoint.verify`, and
`connector.test`, matching the safe actions its blank-stack console offers. It does
not enable `connector.deploy`; an evaluation install must not gain appliance-write
authority merely because it started successfully. A host-family `connector.test`
uses the enrolled host agent's local exec profile to validate roots and commands and
performs only a read-only TLS handshake; it cannot write or reload. Production
remains empty and fail-closed until an operator chooses each kind.

See [Getting started](getting-started.md) for the blank Compose stack's published
agent-channel port and the local CA-pinning steps to reach it from an agent CLI.

### Relay-local CRL and OCSP cache

A certificate enrolled with the `network` role may serve revocation data to an
isolated segment. Start it with `--revocation-cache-config <file>`. The JSON file is
limited to 1 MiB, rejects unknown fields, and contains public issuer certificates
and routes—not private keys, tokens, or bind credentials:

```json
{
  "listen": "10.42.0.12:8088",
  "segment": "plant-7",
  "refresh_interval": "5m",
  "issuers": [
    {
      "id": "manufacturing-root",
      "issuer_file": "/etc/trstctl/manufacturing-root.pem",
      "crl": {
        "upstream_url": "https://pki.internal/crl/manufacturing.crl",
        "local_path": "/crl/manufacturing"
      },
      "ocsp": {
        "upstream_url": "https://ocsp.internal/manufacturing",
        "local_path": "/ocsp/manufacturing"
      }
    }
  ]
}
```

Issuer and segment IDs are bounded tokens, every local path must be unique, and the
refresh interval must be between one minute and 24 hours. RFC 1918 and IPv6 ULA
upstreams are allowed because an internal CA is the normal case; loopback,
link-local, metadata-service, multicast, CGNAT, credentials-in-URL, and DNS-rebind
targets remain refused. CRLs are fetched on the refresh interval. OCSP is fetched on
demand and only nonce-free responses are reused. The listener serves no stale or
unverified bytes.

The first mTLS heartbeat already contains the relay's signed, metadata-only cache
status. Read it at `GET /api/v1/revocation/caches` or Protocols → Revocation cache by
segment. That status includes segment, issuer fingerprint, local path, signed time
window, validation time, and request counts. It never includes the upstream URL,
issuer/response bytes, or OCSP request. The older `--crl-cache-*` flags remain for a
single CRL; pair them with `--revocation-cache-segment` so their heartbeat has an
operator-defined segment identity.

For host connector execution, `trstctl-agent --host-exec-profile <file>` also
initializes an encrypted two-generation predecessor ledger. Set
`--host-rollback-dir <absolute-directory>` to choose its durable location; when
omitted it is `host-rollbacks` beside `--key`. Back up or persist that directory
with the agent identity. If it is lost, the exact host predecessor cannot be
reconstructed by the control plane and rollback is refused.

## WASM plugins

The WASM plugin surface is off by default. When enabled, the binary admits only signed
modules whose detached Ed25519 signature verifies against the configured trusted keys.
CA plugins become external CA entries of type `wasm-ca`; DNS-provider plugins become a
served ACME DNS-01 provider that tenant provider configs can select; connector plugins
handle matching deployment work from the outbox.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_PLUGINS_ENABLED` | `false` | Load signed WASM plugins at startup. |
| `TRSTCTL_PLUGINS_CA_DIR` | — | Directory containing signed CA plugin pairs: `<name>.wasm` and `<name>.wasm.sig`. |
| `TRSTCTL_PLUGINS_DNS_DIR` | — | Directory containing signed DNS-provider plugin pairs. Each module becomes a served ACME DNS-01 provider that tenant provider configs can select. |
| `TRSTCTL_PLUGINS_CONNECTOR_DIR` | — | Directory containing signed connector plugin pairs. |
| `TRSTCTL_PLUGINS_DIR` | — | Legacy connector-plugin directory alias. Ignored when `TRSTCTL_PLUGINS_CONNECTOR_DIR` is set. |
| `TRSTCTL_PLUGINS_TRUSTED_KEY_FILES` | — | Comma-separated PEM Ed25519 public keys trusted to sign plugin artifacts. Required when plugins are enabled. |
| `TRSTCTL_PLUGINS_PINNED_DIGESTS` | — | Optional comma-separated SHA-256 artifact digests that must match admitted modules exactly. |
| `TRSTCTL_PLUGINS_CAPABILITIES` | — | Comma-separated capabilities granted to loaded plugins, such as `fs.write` or `net.dial`. Empty grants no privileged host operation. |
| `TRSTCTL_PLUGINS_PATH_PREFIXES` | — | Optional comma-separated filesystem prefixes constraining `fs.read` and `fs.write`. |

## SPIRE upstream authority plugin

When SPIRE should keep serving workload SVIDs but trstctl should own the upstream CA,
configure SPIRE's `UpstreamAuthority "trstctl"` plugin. SPIRE passes this as HCL
`plugin_data` to the `trstctl-spire-upstream-authority` process; these are not trstctl
environment variables.

| Field | Required | Meaning |
| --- | --- | --- |
| `endpoint` | yes | Base URL of the trstctl control plane, for example `https://trstctl.example.com:8443`. The plugin calls `/api/v1/ca/authorities/{id}/intermediates/csr`. |
| `ca_bundle_file` | no | PEM CA bundle used only to verify the HTTPS trstctl endpoint. Set this to trstctl's published internal trust file for a self-signed/private deployment; omit it to use the host's normal trust store. Plain HTTP cannot use this field. |
| `allow_private_cidrs` | no | Exact private network ranges the endpoint is allowed to resolve into, for example `["10.96.42.15/32"]`. Private addresses are blocked by default; link-local, metadata, multicast, unspecified, CGNAT, and IPv6 unique-local addresses remain blocked even if listed. Prefer a host-sized `/32` or `/128` over a whole network. |
| `ca_authority_id` | yes | The trstctl CA authority that signs SPIRE's intermediate CA CSR. |
| `token_file` | yes | File containing a trstctl API token with `certs:issue`. Mount it as a secret file readable only by the SPIRE server process. |
| `common_name` | no | Subject common name for the SPIRE intermediate; defaults to `SPIRE Server CA`. |
| `ttl_seconds` | no | Intermediate CA TTL. If SPIRE sends a preferred TTL, the plugin honors SPIRE's value for that mint. |
| `max_path_len` | no | Path length for the SPIRE intermediate; use `0` so it can sign workload leaves but not another CA below it. |
| `permitted_dns_domains` | no | Optional DNS name constraints copied into the intermediate CA profile. |
| `extended_key_usages` | no | Optional extended key usages to request for the intermediate profile. |
| `idempotency_prefix` | no | Prefix for the stable `Idempotency-Key`; defaults to `spire-upstream`. |

Example:

```hcl
UpstreamAuthority "trstctl" {
  plugin_cmd = "/opt/spire/plugins/trstctl-spire-upstream-authority"
  plugin_data {
    endpoint = "https://trstctl.example.com:8443"
    ca_bundle_file = "/run/secrets/trstctl-server-ca.pem"
    allow_private_cidrs = ["10.96.42.15/32"]
    ca_authority_id = "11111111-1111-1111-1111-111111111111"
    token_file = "/run/secrets/trstctl-spire-token"
    common_name = "SPIRE Server CA"
    ttl_seconds = 3600
    max_path_len = 0
    permitted_dns_domains = ["example.org"]
  }
}
```

## Rate limiting

A per-tenant, PostgreSQL-backed rate limiter sheds load on the guarded routes
(429 + `Retry-After`). See [Operations & resilience](operations.md) for the model
and the bulkheads it complements.

ACME also has protocol-local abuse budgets above because its public nonce/account/order
routes are not REST API routes. The protocol bulkhead limits concurrent work; the
ACME quota knobs bound retained ACME protocol state.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_RATE_LIMIT_ENABLED` | `true` | Turn per-tenant rate limiting on/off. |
| `TRSTCTL_RATE_LIMIT_REQUESTS` | `600` | Burst/budget per window, per tenant. |
| `TRSTCTL_RATE_LIMIT_WINDOW` | `1m` | The refill window (Go duration). |

When enabled, `requests` must be positive and `window` a valid positive duration,
or the control plane fails fast at startup.

## Bulkheads

Each subsystem runs on its own bounded worker pool. `workers` caps concurrent
work; `queue` caps accepted backlog before trstctl rejects fast with structured
backpressure. Every value must be positive. Defaults are conservative for a
single-node or small HA deployment; larger fleets should raise only the subsystem
that is actually saturating.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_BULKHEAD_API_WORKERS` / `TRSTCTL_BULKHEAD_API_QUEUE` | `8` / `256` | Cheap REST/API work. Keep this protected from heavy query, protocol, and agent waves. |
| `TRSTCTL_BULKHEAD_PROJECTIONS_WORKERS` / `TRSTCTL_BULKHEAD_PROJECTIONS_QUEUE` | `2` / `128` | Served event-log projection tail ownership and restart work. A saturated projections pool sheds tail starts and retries, while the durable cursor preserves ordered projection. Raise workers only when PostgreSQL and NATS have headroom. |
| `TRSTCTL_BULKHEAD_OUTBOX_WORKERS` / `TRSTCTL_BULKHEAD_OUTBOX_QUEUE` | `4` / `256` | Default for every outbox family and the independent “other” lane (`ca.*`, revocation, DNS automation, ITSM, discovery, and plugin-owned destinations). Existing deployments can keep using only this pair. |
| `TRSTCTL_BULKHEAD_OUTBOX_EXTERNAL_CA_WORKERS` / `TRSTCTL_BULKHEAD_OUTBOX_EXTERNAL_CA_QUEUE` | inherits outbox | Override only `external-ca.*` issuance calls. |
| `TRSTCTL_BULKHEAD_OUTBOX_CONNECTORS_WORKERS` / `TRSTCTL_BULKHEAD_OUTBOX_CONNECTORS_QUEUE` | inherits outbox | Override `connector.*`, including deploy, rollback, test, and right-size calls. |
| `TRSTCTL_BULKHEAD_OUTBOX_SECRETS_WORKERS` / `TRSTCTL_BULKHEAD_OUTBOX_SECRETS_QUEUE` | inherits outbox | Override dynamic-secret provider calls (`dynsecret.*`). |
| `TRSTCTL_BULKHEAD_OUTBOX_SECRET_SYNC_WORKERS` / `TRSTCTL_BULKHEAD_OUTBOX_SECRET_SYNC_QUEUE` | inherits outbox | Override outbound secret-sync calls (`secret.sync*`) without sharing dynamic-secret workers. |
| `TRSTCTL_BULKHEAD_OUTBOX_MANAGED_KEYS_WORKERS` / `TRSTCTL_BULKHEAD_OUTBOX_MANAGED_KEYS_QUEUE` | inherits outbox | Override durable managed-key/HSM commands (`managedkey.*`). |
| `TRSTCTL_BULKHEAD_OUTBOX_TRANSPARENCY_WORKERS` / `TRSTCTL_BULKHEAD_OUTBOX_TRANSPARENCY_QUEUE` | inherits outbox | Override transparency publication (`transparency.*`). |
| `TRSTCTL_BULKHEAD_OUTBOX_CODE_SIGNING_WORKERS` / `TRSTCTL_BULKHEAD_OUTBOX_CODE_SIGNING_QUEUE` | inherits outbox | Override code-signing commands (`codesign.*`) without sharing transparency workers. |
| `TRSTCTL_BULKHEAD_OUTBOX_NOTIFICATIONS_WORKERS` / `TRSTCTL_BULKHEAD_OUTBOX_NOTIFICATIONS_QUEUE` | inherits outbox | Override operator notifications (`notification.*`). |
| `TRSTCTL_BULKHEAD_OUTBOX_AUDIT_FEEDS_WORKERS` / `TRSTCTL_BULKHEAD_OUTBOX_AUDIT_FEEDS_QUEUE` | inherits outbox | Override scheduled native audit delivery (`audit.feed.*`). A stopped SIEM cannot consume connector, notification, issuance, or API capacity. |
| `TRSTCTL_BULKHEAD_OUTBOX_FLEET_REISSUANCE_WORKERS` / `TRSTCTL_BULKHEAD_OUTBOX_FLEET_REISSUANCE_QUEUE` | inherits outbox | Override the bounded H2 incident action lane, including exact predecessor revocation (`incident.fleet_reissuance.*`). |
| `TRSTCTL_BULKHEAD_OUTBOX_TENANT_SEAL_WORKERS` / `TRSTCTL_BULKHEAD_OUTBOX_TENANT_SEAL_QUEUE` | inherits outbox | Override the zero-egress tenant seal commit worker (`tenantseal.seal`). It proves the accepted result is durable before acquiring the cross-replica seal fence. |
| `TRSTCTL_BULKHEAD_SIGNING_WORKERS` / `TRSTCTL_BULKHEAD_SIGNING_QUEUE` | `4` / `64` | Control-plane work waiting on signer RPC. Do not set this above signer capacity. |
| `TRSTCTL_BULKHEAD_QUERY_WORKERS` / `TRSTCTL_BULKHEAD_QUERY_QUEUE` | `4` / `64` | Heavy graph/risk/read queries that scale with inventory size. |
| `TRSTCTL_BULKHEAD_POLICY_WORKERS` / `TRSTCTL_BULKHEAD_POLICY_QUEUE` | `4` / `64` | OPA/Rego policy gate work. Saturation fails closed rather than blocking issuance. |
| `TRSTCTL_BULKHEAD_PROTOCOLS_WORKERS` / `TRSTCTL_BULKHEAD_PROTOCOLS_QUEUE` | `8` / `256` | ACME/EST/SCEP/CMP/SPIFFE/SSH/TSA enrollment protocol work. |
| `TRSTCTL_BULKHEAD_AGENT_WORKERS` / `TRSTCTL_BULKHEAD_AGENT_QUEUE` | `16` / `1024` | Agent heartbeat and renewal fan-in. Raise this first for large agent fleets. |
| `TRSTCTL_BULKHEAD_CBOM_WORKERS` / `TRSTCTL_BULKHEAD_CBOM_QUEUE` | `4` / `64` | CBOM TLS/config scans. Raise only when broad crypto-inventory sweeps are saturating and PostgreSQL/NATS have headroom. |

Fleet-size guidance:

| Shape | Starting point |
| --- | --- |
| Single-node eval or small production | Use defaults; tune only after `trstctl_*_bulkhead_*` rejection metrics show pressure. |
| About 1k agents | Increase agent queue first (for example 2048), then agent workers if PostgreSQL/signing have headroom. |
| Very large fleets | Scale agent, protocols, CBOM, and outbox independently; keep API workers modest so operator traffic stays responsive while waves shed elsewhere. |

`trstctl --check-config` prints the effective `bulkheads.<subsystem>.workers` and
`bulkheads.<subsystem>.queue` values, so CI/CD can diff the resolved runtime limits
before a rollout.

Every outbox family owns a separate queue and worker set even when all limits are
inherited from `bulkheads.outbox`. In plain terms, a connector endpoint that stops
answering can fill only the connector lane; it cannot occupy the workers that issue
through an upstream CA, synchronize a secret, publish code-signing evidence, or page
an operator. JSON config may override a family with `outbox_external_ca`,
`outbox_connectors`, `outbox_secrets`, `outbox_secret_sync`,
`outbox_managed_keys`, `outbox_transparency`, `outbox_code_signing`, or
`outbox_notifications`, `outbox_audit_feeds`, `outbox_tenant_seal`, or
`outbox_fleet_reissuance` inside `bulkheads`.

## Config file

Any of the above can also be set in a JSON file named by `TRSTCTL_CONFIG_FILE`;
environment variables override file values, which override defaults.

```json
{
  "server": { "addr": ":8443" },
  "postgres": { "mode": "external", "dsn": "postgres://..." },
  "nats": { "mode": "external", "url": "nats://..." },
  "telemetry": { "enabled": false, "instance_id_file": "data/telemetry/instance-id" }
}
```
