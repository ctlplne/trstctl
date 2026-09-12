# Deployment connectors — get the renewed certificate onto the thing that needs it

## What it is

Issuing a [certificate](../glossary.md) is only half the job; it has to actually land
on the server, load balancer, or appliance that will use it. A
**[deployment connector](../glossary.md#connector)** is a small implementation that
knows how to install a credential on one kind of [target](../glossary.md#destination-deployment-target) — write
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
with the [execution vantage](../glossary.md#execution-vantage) from the closed connector census. The control-plane worker
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

### Verified relay plugins

A network relay reports what its running plugin loader actually accepted through a
signed, metadata-only census on its mTLS heartbeat. Each row contains the stable
plugin name, verified module digest, publisher fingerprint, the
`network_relay_wasm` execution context, and its effective grants and normalized
constraints. This list comes from the same load operation that checked the module
signature and started the WASM instance; scanning a directory would only prove that
a file exists, not that the runtime trusted and loaded it.

The relay signs the tenant, its certificate common name, the normalized list, and
the issued-at time with its agent identity. The control plane independently takes
the tenant and relay identity from the authenticated certificate, rejects tampered,
stale, cross-tenant, or host-agent reports, and projects an accepted heartbeat from
the immutable event stream. A signed empty census is explicit evidence that the
relay currently loaded no partner modules. A missing census means the agent version
cannot report this state; the two cases are not collapsed.

`GET /api/v1/connectors/catalog` returns these per-relay rows in `relay_plugins`,
with cursor pagination. The **Verified relay plugins** table on Connectors shows the
relay identity, signature status, signer certificate fingerprint, plugin provenance,
execution context, effective grants and normalized constraints, and report time.
This surface contains no module bytes, publisher keys, credential bytes, or secrets.
It is evidence of what the relay loaded, not a control-plane mechanism for pushing
modules or widening an operator-owned grant.

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

### Console journey: Where credentials are installed

The `/connectors` page is named **Where credentials are installed** because the
operator's first question is not “which plugins exist?” It is “which systems can
trstctl update, and what proof says those systems are healthy?” The opening view
therefore shows the configured-destination count, the count with listener
verification evidence, and how many connector types can execute rollback. A target
without verification evidence is never described as healthy.

The first view has one action, **Add destination**. Its dialog explains that saving a
destination does not deploy a credential. It accepts a non-secret name, one connector
type, and the connector's exact JSON configuration; credential fields must be
`secret://` references. Cancel closes the dialog without an API mutation. Binding,
testing, deploying, and rolling back remain separate reviewed actions.

Three closed sections keep implementation machinery available without making it the
default reading path:

- **Destinations and safe actions** loads identities only when opened, then exposes
  target evidence, binding, **Preview changes (no writes)**, deploy,
  **Review restore**, and the exact activity timeline. Preview shows a real
  `dry_run_planned` or `dry_run_blocked` receipt when the target agent or relay
  answers. If no target-side executor is enabled, it says **Configuration valid —
  target not contacted** and explicitly refuses to treat that local check as
  deployment readiness. An asynchronous preview is refreshed through its exact
  idempotency-linked result receipt, so a different target's answer cannot be
  substituted. The lookup filters by the exact receipt key on the server; it does
  not depend on which page of tenant history is loaded. API clients can use
  `GET /api/v1/connectors/deliveries?idempotency_key=<URL-encoded-key>` with the
  queued preview's key followed by `:result`. An empty result means no matching
  result has been projected yet. This read requires `connectors:read` and remains
  scoped to the authenticated tenant.
- **Health, retries, and rollback** loads delivery receipts, listener verification,
  key custody, and outbox-circuit evidence only when opened. These are distinct
  observations; a successful outbox attempt does not silently stand in for a listener
  check.
- **Connector capabilities and plugin evidence** retains the complete registry,
  execution vantage, rollback behavior, device proof, relay-migration disposition,
  signed publisher identity, and effective plugin grants.

The closed sections reduce first-view noise only. They do not remove APIs, evidence,
or state-changing controls, and they do not prefetch the larger expert datasets until
an operator asks to inspect them.

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

`target deploy` is not a private-key recovery command. For a `requested` identity,
it binds the target first and starts issuance so the new certificate and its private
key move directly into one sealed connector job. If an identity was already issued
before that credential-bearing path existed, trstctl does not have a retained private
key to copy: the deploy call returns `409`, leaves state and queues unchanged, and
tells the operator to wait for an already-bound issuance or renew/reissue after
binding. A running renewal is also left alone; its successor will deploy through its
own bound job. This refusal prevents the console from saying **Deployed** when no
executor received a credential.

`target test` is an effect-free dress rehearsal from the machine or network that
would perform the real deployment. Enable `connector.test` as a claimable job kind
in addition to enrolling the required agent role. For all 14 host-vantage families,
the host agent validates the exact target fields, confirms every path and logical
command fits its operator-owned `--host-exec-profile`, and, when configured,
handshakes `verify_address` using `verify_server_name`. With no `verify_address`,
the plan says the deploy can run but live-state verification is not configured; it
never upgrades that omission into a claim that the certificate is serving. It does
not write a file, run a command, call `Deploy`, or redeem certificate/private-key
material. A host secret needed to open the target, such as a Java keystore password
reference, is redeemed only for that one attempt. Network-relay appliance tests
instead redeem the appliance-management credential and perform the connector's
read-only probe. A ready
test returns `dry_run_planned` with the later mutation list; an unreachable target,
missing grant, or other deterministic prerequisite returns terminal
`dry_run_blocked` rather than retrying forever. Signed plugins that do not declare a
zero-write testing contract fail closed without being invoked.

The console keeps recovery separate from deployment. **Review restore** opens a
confirmation that names the exact destination, identity, and operator reason; no
restore is queued by opening it. Identity choices and the review show the lifecycle
state and full identity ID so same-name replacements remain distinguishable.
**Queue restore** uses the served rollback route.
The first response may say only `rollback_queued`: that is waiting state, not
success. The console reports success only from a later `rolled_back` receipt written
after the required agent or relay restores the proven predecessor. While queued, the
console rereads that exact receipt every three seconds while the tab is visible.
It stops polling at an attempt result or read failure; **Check restore result**
remains available after a failure because the same job may retry. It only reads
the receipt and never queues another restore. A mismatched or unavailable
receipt is not shown as a successful recovery. Repeating a pending restore joins
its existing job and preserves any recorded attempt result. Re-arming a finished
job keeps its result ID; its next claim uses a new signed agent attempt. A delayed
result from the prior execution cannot complete the new request, and replaying
older evidence cannot move the displayed receipt backward. On the first upgrade
with older rollback receipts, startup rebuilds the read model from retained event
history before serving; a failed rebuild leaves the existing model intact and
refuses startup. This also applies when restoring an older snapshot. Connector
families without an executable restore path show the manual boundary and keep the
button disabled; the API also fails closed instead of recording a rollback-shaped
success.

Disabling a destination pauses the agent-claimable work already queued for it:
deploys and rollbacks stamped with that destination's lane are handed to no agent
while it is disabled, nothing is dropped, and the same rows resume unchanged the
moment it is enabled again. The Jobs page keeps showing them as pending meanwhile.

The REST surface is `/api/v1/connectors/targets` for CRUD,
`/api/v1/identities/{id}/connector-target` for identity binding, and
`/api/v1/connectors/targets/{id}/{test,deploy,rollback}` for actions; CRUD and binding
are immutable events (`deployment_target.upserted`, `deployment_target.deleted`,
`identity.connector_target_bound`) projected into the read model, so disaster recovery
rebuilds routing from the event log. The effect-free
`POST /api/v1/lifecycle/endpoint-bindings/preview` resolves one exact configured
issuer and destination revision and fingerprints the proposed identity, custody,
writes, queued effects, recovery, and verification. The preview also compares
the single requested DNS name with a host target's
`verify_server_name`. A mismatch is rejected before issuance, file replacement, or
reload, because that deployment is guaranteed to fail its own TLS proof. The paired
`POST /api/v1/lifecycle/endpoint-bindings` accepts only that unchanged preview: it
creates or reuses the target, creates the X.509 identity for an existing owner, pins
the selected built-in, private, or external issuer, binds the route, and queues the
normal `ca.issue`/`connector.deploy` intents. Scheduled renewal reuses the
leader-only `ca.renew` path and the same issuer selection, delivering the successor
to the same binding and producing a second connector receipt. The worker fails
closed when that issuer is unavailable; it never silently substitutes another CA.

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

### Host-executed keys

Host-executed targets (the file-and-reload families above) also accept the custody
and verification keys the enrolled host agent honours: `"executor": "agent"` makes
the agent generate the private key on the host and submit only a CSR;
`required_agent_role` (`host`) names the enrolment role that may claim the work; and
`verify_address` plus `verify_server_name` tell the agent which listener to
re-handshake after the reload, so a receipt is backed by an independent TLS check.
Use `executor: agent` whenever the identity's CA is external: an external CA
answers asynchronously, and the endpoint lifecycle preview refuses control-plane key
custody for an external CA on a host connector rather than risk a certificate whose
key no longer exists. The partner lab's working Apache target is:

```json
{"executor":"agent","required_agent_role":"host",
 "cert_path":"/lab/tls/apache.crt","key_path":"/lab/tls/apache.key",
 "verify_address":"127.0.0.1:10443","verify_server_name":"apache.partner-lab.example.com"}
```

For a host-executed Traefik destination, also set `config_path` to the existing
file-provider YAML or TOML document that references `cert_path` and `key_path`,
for example `/etc/traefik/dynamic.yml`. Traefik does not reliably reload when only
those referenced certificate files change. The connector rewrites the same
document after installing the files to notify the watcher, preserving its content.
The document must be inside the agent's allowed roots and readable and writable
there. Preview refuses a missing `config_path` before any certificate is installed.

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
`verify_address`. The four migrated appliance families use object re-bind instead.
Cisco, FortiGate, Palo Alto, and the three cloud stores have no executable rollback;
their support rows say so, and a refusal records no rollback-shaped success.

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
- **Host target testing:** `connector.test` is separately enabled. It checks target
  reachability and local authority without granting `connector.deploy`; a green test
  is a plan, not proof that a certificate was installed.
- **Control-plane cloud target testing:** AWS ACM, Azure Key Vault, and GCP
  Certificate Manager previews run on the bounded control-plane outbox worker.
  Each uses the exact saved target revision and a one-attempt secret lease for an
  authenticated, provider-specific read-only operation, then returns the later
  import plan. Provider I/O never occurs in the request handler, and preview never
  calls the connector's deploy method.
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
