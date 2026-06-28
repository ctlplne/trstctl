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
connector plugins, and otherwise records an `unrouted` receipt. If a native registry entry
owns the connector and the payload carries `cert_pem` plus `key_pem`, the worker runs the
connector at-least-once and records a `delivered` or `failed` receipt. Each connector must
be idempotent on the certificate's fingerprint, so a retry never breaks anything; a
conformance suite proves every connector names itself, declares ≥1 capability, deploys, is
idempotent on re-deploy, and denies an ungranted operation. Connectors compute fingerprints
and any request signing through the single crypto path — none of them do crypto directly.

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

```sh
trstctl connector target create \
  --name edge/prod/payments \
  --connector nginx \
  --config-json '{"credential_ref":"secret://connectors/nginx/edge","host":"edge-1.internal"}'

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

Connectors themselves are wired at process composition time: register the trusted
in-process connectors you need, give each one the narrow `Ops` implementation it is
allowed to use, and pass that registry to `server.Build`. The same served outbox worker
that handles CA issuance and revocation then drives deployment.

```go
reg := connector.NewRegistry(opsFor) // opsFor returns real HTTP/fs/exec Ops per connector.
reg.Register(nginx.New(nginx.WithBinary("/usr/sbin/nginx")))
reg.Register(acm.New("us-east-1", acm.Credentials{ /* ... */ }))

srv, err := server.Build(ctx, server.Deps{
    Store: store,
    Log:   log,
    ConnectorRegistry: reg,
})
```

When an outbox payload contains the issued certificate and private key bytes, the matching
connector runs inside its sandbox and the new certificate lands on the target. Metadata-only
lifecycle transitions still produce receipts, but they do not mutate a target unless a
deployment payload carries the credential bytes; this is deliberate, because the served CA
destroys generated private keys after issuance. To add a target trstctl doesn't ship,
follow the [connector authoring guide](../guides/connector-authoring.md).

## Pitfalls & limits

- **Serving status:** the SDK and all shipped connectors (initial + appliance) are wired
  into the served outbox path through `server.Deps.ConnectorRegistry`, and signed WASM
  connector plugins remain a second served path for third-party code. Tenant-scoped
  target CRUD, test, deploy, rollback, and identity binding are served; target mutation
  still requires a native connector registry or signed plugin owner.
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
  `traefik`, `envoy`, `postfix`, `aws-acm`, `azurekv`, `gcpcm`, `javakeystore`, `f5`.
- **Appliance connectors (F27):** `netscaler`, `cisco`, `fortigate`, `paloalto`.
- **Outbox destination:** `connector.deploy`.
- **Guide:** [Authoring a connector](../guides/connector-authoring.md).

## See also

[Lifecycle & PQC](lifecycle-and-pqc.md) (what triggers deployment) ·
[Extensibility & plugins](extensibility-plugins.md) (the capability sandbox model) ·
[Connector authoring guide](../guides/connector-authoring.md) ·
glossary: [certificate](../glossary.md), [outbox](../glossary.md),
[plugin / WASM sandbox](../glossary.md)

**Covers:** F7, F27
