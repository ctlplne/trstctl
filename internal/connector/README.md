# Connector SDK

A *connector* deploys a renewed credential to a target — NGINX, Apache, IIS,
HAProxy, F5 BIG-IP, AWS ACM, Azure Key Vault, GCP Certificate Manager. The SDK
extracts everything those share so each connector (S5.6+) is a small change:
implement one seam and declare the capabilities it needs.

## Writing a connector

Implement `Connector`:

```go
type Connector interface {
    Name() string
    Capabilities() pluginhost.Grant
    Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error
}
```

- **`Capabilities`** declares the least set of capabilities the connector needs,
  using the same grant model as WASM plugins (`pluginhost.Grant`): `CapFSWrite`
  (path-constrained), `CapNetDial`, `connector.CapExec`.
- **`Deploy`** installs `dep` (cert + key PEM) using only `Sandbox` operations —
  `Send` (to a network target), `WriteFile` (to a path), `Exec` (a reload). Each
  is checked against the grant; anything outside it returns `ErrDenied`. Deploy
  must be idempotent on `dep.Fingerprint` (replaying a deploy leaves the target
  in the same state — delivery is at-least-once).

See `example/` for a complete file-plus-reload connector (the NGINX/Apache
shape).

## Capability discipline

A connector can only ever do what its grant permits — the same sandbox
discipline the plugin host enforces for WASM plugins. The `Sandbox` gates every
privileged operation, so a bug or a compromised connector cannot exceed its
declared grant. `Conformance` verifies a connector is least-privilege: it must
deploy with the capabilities it declares and have everything else denied.

## Delivery (AN-6)

Deployment is outbox-driven. The orchestrator enqueues a `connector.deploy`
message (`EncodeDeploy`) in the same transaction as the lifecycle state change,
and a worker hands it to the connector via a `Registry`:

```go
reg := connector.NewRegistry(opsFor) // opsFor supplies each connector's real Ops
reg.Register(myconnector.New(...))
outbox.HandlerFunc(func(ctx, m) error { return reg.Handle(ctx, m.Payload) })
```

At-least-once delivery plus an idempotent `Deploy` make the effect exactly-once.

## Conformance and testing

Run the shared suite against your connector, driven by the in-memory target
harness (`MemoryOps`):

```go
report := connector.Conformance(ctx, myconnector.New(...))
if !report.OK() { /* fail */ }
```

It checks that the connector names itself, declares at least one capability,
deploys a credential, is idempotent over persistent target state, and denies
operations outside its grant.
