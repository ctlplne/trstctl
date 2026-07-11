# Deployment connectors — get the renewed certificate onto the thing that needs it

## What it is

Issuing a [certificate](../glossary.md) is only half the job; it has to actually land
on the server, load balancer, or appliance that will use it. A **deployment connector**
is a small plugin that knows how to install a credential on one kind of target — write
it to nginx and reload, import it into AWS Certificate Manager, push it to an F5
load balancer — and trstctl ships a set of them plus an SDK for writing your own.

The mental model: the [CA](../glossary.md) is a locksmith who cuts a new key; a
connector is the courier who drives to the right door and fits it, then checks the door
still opens. Critically, each courier is given a **narrow, sealed instruction packet**
(only the capabilities it needs) so it can't wander into rooms it has no business in.

## Why it exists

The painful, error-prone part of certificate management is the "last mile": copying a
new certificate to dozens of different systems, each with its own file format, API, and
reload dance — and doing it reliably, repeatedly, without an outage. Connectors make
that last mile automatic and *safe*: deployment is driven by the
[outbox](../glossary.md) so it can't be lost, it's idempotent so a retry doesn't break
anything, and each connector is sandboxed so a buggy or hostile one can't read your
database or your keys.

## How it works

### The connector SDK and its sandbox

Every connector implements exactly three methods: `Name()`, `Capabilities()`, and
`Deploy(ctx, sandbox, deployment)`. The `deployment` carries the certificate and key as
wipeable `[]byte` buffers — held in memory that is zeroed after use, never a string — plus
a fingerprint. Everything else — policy, sandboxing, delivery — comes from the SDK, so a
connector is tiny and focused.

The safety comes from **capability grants**, the same model that governs WASM
[plugins](extensibility-plugins.md). A connector declares the narrow set of capabilities
it needs — `fs.write` to a specific path prefix, `net.dial` to a specific host,
`process.exec` to run a reload — and at runtime the sandbox checks *every* operation
against that grant. Anything outside it returns `ErrDenied`. An nginx connector that
declares "write to `/etc/nginx/` and exec `nginx`" literally cannot open a socket or
read elsewhere.

Delivery uses reliable, journaled delivery: the orchestrator writes a `connector.deploy`
message in the *same transaction* as the state change that requested deployment — so a
crash can't drop it — and the running binary's outbox worker decodes it. The worker first
checks the trusted native `ConnectorRegistry`, then the provenance-verified signed WASM
connector plugins. If neither owns the name, the worker records a `failed` receipt and leaves
the row pending; it never acknowledges configured work without touching a receiver. A
`queued` receipt has `attempts=0` and means only that durable work exists, not that deployment
happened. Proven deterministic/readback connectors may retry after a crash. Import, exec, and
signed-plugin receivers without an enforced replay contract are claimed before I/O and become
operator-indeterminate after an ambiguous failure instead of risking a duplicate mutation.
The production registry's replay classification is closed and linked to repeated-deploy tests.
Connectors compute fingerprints and request signing through the single crypto path — none of
them do crypto directly.

Retries use capped exponential backoff with per-row jitter, so a failed CA, webhook, or
connector does not receive a synchronized retry storm. The worker also keeps a
tenant/destination circuit breaker: after repeated failures it opens the circuit,
skips new claims for that tenant/destination, then allows a half-open probe when the
window expires. Operators can inspect the live circuit state with
`GET /api/v1/connectors/outbox-circuits`; Prometheus exposes state transitions through
`trstctl_outbox_circuit_transitions_total{tenant_id,destination,from,to}`.

### The initial connector set (F7)

The first cohort covers the most common deployment targets, in two shapes — *write a
file and reload* and *call a cloud/appliance API*:

- **Web servers:** nginx, Apache, Caddy, HAProxy, IIS, and Traefik — write the cert/key
  (or a PKCS#12/PFX), validate the config, and gracefully reload or update the dynamic
  file provider.
- **Cloud certificate stores:** AWS Certificate Manager (`ImportCertificate`, SigV4),
  Azure Key Vault (import via REST), GCP Certificate Manager (with long-running-operation
  polling).
- **Other targets:** Java KeyStore (deterministic PKCS#12/JKS files), Envoy
  (SDS/config push), Postfix and Dovecot (validated mail-server reload), and F5 BIG-IP
  (upload + install + bind to the SSL profile via iControl REST).

### Additional connectors (F27)

The second cohort adds network appliances that all speak HTTPS APIs rather than the
file-and-reload pattern: **Citrix NetScaler/ADC** (NITRO REST), **Cisco ASA/ISE**
(ERS REST), **Fortinet FortiGate/FortiWeb** (FortiOS REST), and **Palo Alto PAN-OS**
(XML API — which the connector parses carefully, because PAN-OS reports failures inside
HTTP 200 responses). These declare only `net.dial` to their appliance host, nothing
else.

## Use it

Tenant operators create non-secret deployment targets through the served API, CLI, or
console. A target names the connector, the route name, and references to credentials or
operator-managed endpoint config; it does not store passwords, tokens, private keys, or
certificate key bytes.

The control-plane operator first enables the native connector and, for a local
file/reload target, defines the exact roots and executables that tenant target rows may
use. This is process configuration, so a tenant cannot grant itself a new filesystem
root or command:

```json
{
  "connectors": {
    "enabled": ["nginx"],
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
    }
  }
}
```

Then a tenant with `connectors:write` creates the target with the connector's strict
target schema:

```sh
trstctl connector target create \
  --name edge/prod/payments \
  --connector nginx \
  --config-json '{"profile":"nginx-prod","cert_path":"/etc/nginx/tls/payments.crt","key_path":"/etc/nginx/tls/payments.key"}'

trstctl connector target bind --identity "$IDENTITY_ID" --target "$TARGET_ID"
trstctl connector target test --target "$TARGET_ID"
trstctl connector target deploy --identity "$IDENTITY_ID" --target "$TARGET_ID"
trstctl connector target rollback --identity "$IDENTITY_ID" --target "$TARGET_ID"
```

The REST surface is `/api/v1/connectors/targets` for CRUD,
`/api/v1/identities/{id}/connector-target` for identity binding, and
`/api/v1/connectors/targets/{id}/{test,deploy,rollback}` for actions. Target CRUD and
binding are immutable events (`deployment_target.upserted`,
`deployment_target.deleted`, `identity.connector_target_bound`) projected into the read
model, so disaster recovery rebuilds the same deployment routing from the event log.

For a one-call lifecycle workflow, `POST /api/v1/lifecycle/endpoint-bindings`
creates or reuses the deployment target, creates the X.509 identity for an existing
owner, binds that identity to the target, and queues the normal `ca.issue` and
`connector.deploy` lifecycle intents. Scheduled renewal remains the same leader-only
`ca.renew` path, so the renewed successor is delivered back to the same endpoint
binding and produces a second connector receipt.

The shipped `trstctl` composition constructs the trusted native registry from
`connectors.enabled`; applications do not need to call `connector.NewRegistry`.
Remote targets put only `secret://name` references in target JSON. The referenced
credential is read from that tenant's encrypted secret store into locked memory for
one outbox attempt, then destroyed. For example, an F5 target uses
`{"endpoint":"https://bigip.internal","client_ssl_profile":"payments","username":"svc-trstctl","password_ref":"secret://connectors/f5/password"}`.
Private management endpoints must also be admitted by the operator-owned
`connectors.allow_private_cidrs` list. Plain HTTP is rejected unless the operator
explicitly enables the development/emulator override for a loopback URL. That client
can resolve and dial only loopback addresses; private CIDR grants never widen the
plaintext exception. Do not enable it in production.

The target JSON is closed and provider-specific; unknown fields fail the attempt
instead of being ignored:

| Connector(s) | Required target `config` fields |
| --- | --- |
| `nginx`, `apache`, `caddy`, `traefik`, `postgresql`, `mysql`, `rabbitmq`, `elasticsearch`, `tomcat` | `profile`, `cert_path`, `key_path` |
| `haproxy` | `profile`, `crt_path`, `config_path` |
| `iis` | `profile`, `binding`, `import_dir`; optional `store`, `app_id` |
| `postfix` | `profile`, `postfix_cert_path`, `postfix_key_path`, `dovecot_cert_path`, `dovecot_key_path` |
| `java-keystore` | `profile`, `keystore_path`, `keystore_password_ref`, `alias`; optional `format` (`jks` or `pkcs12`) |
| `envoy` | `endpoint`, `secret_name` |
| `f5` | `endpoint`, `client_ssl_profile`, `username`, `password_ref`; optional `object_name` |
| `netscaler` | `endpoint`, `username`, `password_ref`; optional `file_location` |
| `a10`, `cisco` | `endpoint`, `username`, `password_ref` |
| `kemp`, `fortigate` | `endpoint`, `token_ref` |
| `paloalto` | `endpoint`, `api_key_ref` |
| `aws-acm` | `endpoint`, `region`, `access_key_id`, `secret_access_key_ref`; optional `session_token_ref` |
| `azure-keyvault` | `endpoint`, `bearer_token_ref`; optional `api_version` |
| `gcp-certificate-manager` | `endpoint`, `project`, `location`, `bearer_token_ref`; optional `poll_interval` |

Every `*_ref` in this table is a `secret://name` or
`secret://name?version=N` reference in the same tenant. Every `profile` points to
an operator-owned `connectors.local_profiles` entry. Local profile actions map the
connector's logical command (`nginx`, `apachectl`, `caddy`, `powershell`, `netsh`,
`haproxy`, `systemctl`, `postfix`, `doveconf`, `doveadm`, `pg_ctl`, `mysqladmin`,
`rabbitmqctl`, or `catalina.sh`) to one absolute executable. General-purpose Unix
shells are rejected. IIS may map its native `powershell` action to PowerShell only
when the operator supplies an exact `logical_args` allowlist and a separate exact
`args` execution list with `pass_args: false`; this makes the requested argv a
comparison value and forwards no tenant-derived byte to `-Command`. Symlinked
executables are rejected for every local profile.

For endpoint-binding issue and renewal flows, the issuer builds a credential-bearing
`connector.deploy` payload while the freshly generated private key is still in memory,
then wipes the exported key buffer after the outbox intent is recorded. The matching
connector runs inside its sandbox and the new certificate lands on the target; delivery
receipts keep only identity, route, fingerprint, and status metadata. Metadata-only
operator deploy actions still produce receipts when no credential bytes are available, but
they do not claim target mutation. To add a target trstctl doesn't ship, follow the
[connector authoring guide](../guides/connector-authoring.md).

## Pitfalls & limits

- **Serving status:** the SDK and all 24 shipped connectors (initial + appliance) are
  constructed from `connectors.enabled` by the shipped binary and wired into the served
  outbox path through `server.Deps.ConnectorRegistry`; signed WASM
  connector plugins remain a second served path for third-party code. Tenant-scoped
  target CRUD, test, deploy, rollback, and identity binding are served; target mutation
  requires the matching native connector to be enabled or a signed plugin owner.
- **Grants are deny-by-default.** If a connector seems to "do nothing," check it
  declared the capability for the operation — an ungranted op fails with `ErrDenied`,
  which is the safety net working as designed.
- **Appliance connectors need reachable management endpoints** and credentials scoped to
  certificate import only.
- **Idempotency is keyed on the fingerprint** — deploying the same certificate twice is a
  safe no-op, but that means a connector must converge to the same state on re-deploy.

## Reference

- **SDK:** `Connector{Name, Capabilities, Deploy}`, `Sandbox{WriteFile, Send, Exec,
  Request}`, `Registry`, `Conformance`.
- **Capabilities:** `fs.read`, `fs.write`, `net.dial`, `process.exec` (path/host
  prefix-constrained).
- **Initial connectors (F7):** `nginx`, `apache`, `caddy`, `haproxy`, `iis`,
  `traefik`, `envoy`, `postfix`, `aws-acm`, `azure-keyvault`,
  `gcp-certificate-manager`, `java-keystore`, `f5`.
- **Published catalog breadth (CAP-DEP-09):** first-party native targets also include
  `postgresql`, `mysql`, `rabbitmq`, `elasticsearch`, and `tomcat`, taking the shipped
  production connector catalog to 24 entries before signed third-party plugins.
- **Appliance connectors (F27):** `netscaler`, `a10`, `kemp`, `cisco`,
  `fortigate`, `paloalto`. The served load-balancer set covers F5/BIG-IP,
  Citrix ADC/NetScaler, A10 Thunder/AX, and Kemp LoadMaster target mutation through
  the same outbox plus native-registry or signed-plugin delivery path.
- **Outbox destination:** `connector.deploy`.
- **Guide:** [Authoring a connector](../guides/connector-authoring.md).

## See also

[Lifecycle & PQC](lifecycle-and-pqc.md) (what triggers deployment) ·
[Extensibility & plugins](extensibility-plugins.md) (the capability sandbox model) ·
[Connector authoring guide](../guides/connector-authoring.md) ·
glossary: [certificate](../glossary.md), [outbox](../glossary.md),
[plugin / WASM sandbox](../glossary.md)

**Covers:** F7, F27
