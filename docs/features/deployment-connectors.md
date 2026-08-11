# Deployment connectors — get the renewed certificate onto the thing that needs it

## What it is

Issuing a [certificate](../glossary.md) is only half the job; it has to actually land
on the server, load balancer, or appliance that will use it. A **deployment connector**
is a small plugin that knows how to install a credential on one kind of target — write
it to nginx and reload, import it into AWS Certificate Manager, push it to an F5 load
balancer — and trstctl ships a set of them plus an SDK for writing your own.

The mental model: the [CA](../glossary.md) cuts a new key; a connector is the courier
who drives it to the right door and fits it, carrying only a narrow, sealed
instruction packet so it can't wander into rooms it has no business in.

## Why it exists

The painful, error-prone part of certificate management is the "last mile": copying a
new certificate to dozens of systems, each with its own format, API, and reload dance,
reliably and without an outage. Connectors make that automatic and safe: deployment is
driven by the [outbox](../glossary.md) so it can't be lost, it's idempotent so a retry
can't break anything, and each connector is sandboxed so a buggy or hostile one can't
reach your database or keys.

## How it works

### The connector SDK and its sandbox

Every connector implements exactly three methods: `Name()`, `Capabilities()`, and
`Deploy(ctx, sandbox, deployment)`. The `deployment` carries the certificate and key as
wipeable `[]byte` buffers, zeroed after use, plus a fingerprint; everything else comes
from the SDK, so a connector stays tiny and focused.

Sandboxing uses the same [capability-grant model](extensibility-plugins.md) as
trstctl's WASM plugins: a connector declares the narrow capabilities it needs —
`fs.write` to a path prefix, `net.dial` to a host, `process.exec` to run a reload — and
the sandbox checks every operation against that grant, denying anything outside it
with `ErrDenied`.

Delivery is reliable and journaled: the orchestrator writes a `connector.deploy`
message in the *same transaction* as the state change that requested deployment, so a
crash can't drop it. Before sealing the credential-bearing payload it stamps the row
with the execution vantage from the closed connector census. The control-plane worker
refuses every row stamped `host` before it opens the payload or looks up a native
connector. An old row without a stamp is classified from its connector family and is
refused the same way; an unknown stamp also fails closed. This means the one row cannot
race between the control plane and a host agent, and a missing or offline host agent
leaves it visibly pending instead of silently writing the control-plane filesystem.

An enrolled host-role agent claims that durable row over the served mTLS channel,
redeems its sealed credential once for that attempt, and executes the connector on the
machine that actually serves the workload. The shipped host census has 14 families:
the 13 file/reload connectors plus co-resident Envoy SDS. A generated parity test
compares this list with the control-plane vantage census, so a newly classified host
family cannot ship without an agent constructor. Cloud-store work remains in the
control plane; appliance migration keeps its separately documented network-relay gate.

After choosing the permitted execution path, the worker checks the trusted native
`ConnectorRegistry`, then provenance-verified signed WASM plugins. If neither owns the
name it records a `failed` receipt and leaves the row pending; a `queued` receipt has
`attempts=0` and means only that durable work exists, not that deployment happened.
Deterministic/readback connectors may retry after a crash; others without an enforced
replay contract are claimed before I/O and left operator-indeterminate after an
ambiguous failure, avoiding a duplicate mutation. Connectors compute fingerprints and
request signing through the signer boundary; none do crypto directly.

Retries use capped backoff with jitter, and a tenant/destination circuit breaker opens
after repeated failures, skipping new claims until a half-open probe succeeds.
Operators inspect live state with `GET /api/v1/connectors/outbox-circuits`; Prometheus
exposes transitions through
`trstctl_outbox_circuit_transitions_total{tenant_id,destination,from,to}`.

### The initial connector set (F7)

The first cohort covers the most common deployment targets, in two shapes: write a file
and reload, or call a cloud/appliance API.

- Web servers — nginx, Apache, Caddy, HAProxy, IIS, Traefik: write the cert/key (or a
  PKCS#12/PFX), validate the config, and reload or update the dynamic file provider.
- Cloud certificate stores — AWS Certificate Manager, Azure Key Vault, GCP Certificate
  Manager: import via each provider's native API.
- Other targets — Java KeyStore (deterministic PKCS#12/JKS), Envoy (SDS push), Postfix
  and Dovecot (mail-server reload), and F5 BIG-IP (iControl REST bind to the SSL
  profile).

### Additional connectors (F27)

The second cohort adds network appliances that speak HTTPS APIs instead of the
file-and-reload pattern — Citrix NetScaler/ADC, Cisco ASA/ISE, Fortinet
FortiGate/FortiWeb, and Palo Alto PAN-OS — each declaring only `net.dial` to its
appliance host.

## Use it

Tenant operators create non-secret deployment targets through the served API, CLI, or
console. A target names the connector, the route name, and references to credentials
or operator-managed endpoint config; it never stores passwords, tokens, private keys,
or certificate key bytes.

The control-plane operator first enables the native connector. For a local file/reload
target, the operator also enrolls a host-role agent, enables `connector.deploy` in
`agent_channel.claimable_job_kinds`, starts the agent with `--relay-claim`, and places
the exact roots and executables in the file named by `--host-exec-profile`. The profile
lives on the target host because an allowlist for `/usr/sbin/nginx` on the control
plane says nothing about the binary the target host will actually run. Tenant target
rows select a logical profile name but cannot add a root, executable, or argument:

```json
{
  "allowed_roots": ["/etc/nginx/tls"],
  "actions": [{
    "logical_name": "nginx",
    "command": "/usr/sbin/nginx",
    "pass_args": true,
    "timeout_seconds": 15
  }]
}
```

Envoy uses its co-resident HTTP SDS endpoint and does not consume filesystem or exec
permissions, but it is still host-vantage work: the control plane never falls back to
dialing a loopback Envoy endpoint on its own machine. The host executor accepts only
`localhost` or a literal loopback IP, so an Envoy target cannot become arbitrary
network egress from the agent host.

A tenant with `connectors:write` then creates the target with the connector's strict
schema and drives its lifecycle:

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
`/api/v1/connectors/targets/{id}/{test,deploy,rollback}` for actions; CRUD and binding
are immutable events (`deployment_target.upserted`, `deployment_target.deleted`,
`identity.connector_target_bound`) projected into the read model, so disaster recovery
rebuilds routing from the event log. `POST /api/v1/lifecycle/endpoint-bindings` does
the same in one call: it creates or reuses the target, creates the X.509 identity for
an existing owner, binds them, and queues the normal `ca.issue`/`connector.deploy`
intents; scheduled renewal reuses the leader-only `ca.renew` path, delivering the
successor to the same binding and producing a second connector receipt.

The shipped `trstctl` composition builds the trusted native registry from
`connectors.enabled` (applications never call `connector.NewRegistry` directly).
Remote targets carry only `secret://name` references, read from the tenant's encrypted
secret store into locked memory for one outbox attempt then destroyed — as in an F5
target's
`{"endpoint":"https://bigip.internal","client_ssl_profile":"payments","username":"svc-trstctl","password_ref":"secret://connectors/f5/password"}`.
Private endpoints must also be admitted by the operator-owned
`connectors.allow_private_cidrs` list; plain HTTP needs an explicit development-only
loopback override that never widens the plaintext exception in production. Issue and
renewal flows keep the same discipline: the issuer builds the credential-bearing
`connector.deploy` payload while the key is in memory, wipes the exported buffer once
the outbox intent is recorded, and the connector runs in its sandbox to land the
certificate — receipts keep only identity, route, fingerprint, and status metadata
(metadata-only operator actions still produce a receipt but claim no target mutation).

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

Every `*_ref` is a `secret://name` or `secret://name?version=N` reference in the same
tenant, and every `profile` points to an operator-owned `connectors.local_profiles`
entry, which maps the connector's logical command (`nginx`, `apachectl`, `caddy`,
`powershell`, `netsh`, `haproxy`, `systemctl`, `postfix`, `doveconf`, `doveadm`,
`pg_ctl`, `mysqladmin`, `rabbitmqctl`, or `catalina.sh`) to one absolute executable;
general shells and symlinked executables are rejected. IIS's `powershell` action
additionally requires an exact `logical_args` allowlist and a separate `args` list
with `pass_args: false`, so the requested argv is only ever compared, never forwarded
as a tenant-derived byte to `-Command`. That control-plane entry is the admission and
dry-run copy; the `--host-exec-profile` file is the authority enforced where the
effect runs, so operators keep their roots and actions aligned. To add a target
trstctl doesn't ship, follow the [connector authoring guide](../guides/connector-authoring.md).

Host rollback never sends predecessor key material back through the control
plane. Run the host agent with `--relay-claim --host-exec-profile <file>`; it
keeps active plus one predecessor in an encrypted local ledger at
`--host-rollback-dir` (by default `host-rollbacks` beside the agent key). A
rollback is routed to that exact enrolled agent, serialized with deploys for the
target, restores files, runs the allowlisted reload, and re-handshakes
`verify_address`. The four appliance families listed in the support matrix use
object re-bind instead. Every other family returns a conflict and records no
rollback-shaped success.

## Pitfalls & limits

- **Serving status:** the SDK and all 24 shipped connectors (initial + appliance) are
  constructed from `connectors.enabled` and wired into the served outbox path through
  `server.Deps.ConnectorRegistry`; signed WASM connector plugins are a second served
  path for third-party code. Tenant-scoped target CRUD, test, deploy, rollback, and
  identity binding are served; target mutation needs the matching native connector
  enabled or a signed plugin owner.
- **Host availability:** host-family deploys have no control-plane fallback. If no
  enrolled host-role agent with `connector.deploy` enabled and a usable host profile
  is polling, the row remains pending. Operations shows the queue; this is a safe
  refusal, not a request to place the target's filesystem on the control-plane host.
- **Target evidence:** selecting a target in Connectors shows one time-ordered deploy,
  listener-verification, and rollback timeline. Agent verification rows name the
  certificate identity that produced the signed observation; a delivery receipt alone
  does not claim that the listener is serving the new certificate.
- Grants are deny-by-default: an ungranted operation fails with `ErrDenied` — that's
  the safety net, not a bug, if a connector seems to do nothing.
- Appliance connectors need reachable management endpoints and import-only
  credentials.
- Idempotency is keyed on the fingerprint: redeploying the same certificate is a safe
  no-op, but a connector must converge to the same state.

## Reference

- **SDK:** `Connector{Name, Capabilities, Deploy}`, `Sandbox{WriteFile, Send, Exec,
  Request}`, `Registry`, `Conformance`.
- **Capabilities:** `fs.read`, `fs.write`, `net.dial`, `process.exec` (path/host
  prefix-constrained).
- **Initial connectors (F7):** `nginx`, `apache`, `caddy`, `haproxy`, `iis`,
  `traefik`, `envoy`, `postfix`, `aws-acm`, `azure-keyvault`,
  `gcp-certificate-manager`, `java-keystore`, `f5`; first-party native targets also
  include `postgresql`, `mysql`, `rabbitmq`, `elasticsearch`, and `tomcat`, taking the
  shipped production connector catalog to 24 entries before signed third-party plugins.
- **Appliance connectors (F27):** `netscaler`, `a10`, `kemp`, `cisco`, `fortigate`,
  `paloalto` — covering F5/BIG-IP, Citrix ADC/NetScaler, A10 Thunder/AX, and Kemp
  LoadMaster, delivered through the same outbox plus native-registry/signed-plugin
  path as the initial set.
- **Outbox destination:** `connector.deploy`.
- **Guide:** [Authoring a connector](../guides/connector-authoring.md).

## See also

[Lifecycle & PQC](lifecycle-and-pqc.md) (what triggers deployment) ·
[Extensibility & plugins](extensibility-plugins.md) (the capability sandbox model) ·
[Connector authoring guide](../guides/connector-authoring.md) ·
glossary: [certificate](../glossary.md), [outbox](../glossary.md),
[plugin / WASM sandbox](../glossary.md)

**Covers:** F7, F27
