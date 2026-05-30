# Authoring a connector

A **connector** deploys a renewed credential to a target — NGINX, Apache, IIS,
HAProxy, F5 BIG-IP, AWS ACM, Azure Key Vault, GCP Certificate Manager, and so on.
The connector SDK (package `internal/connector`) extracts everything those share,
so a new connector is a small, focused change: implement one seam and declare the
capabilities it needs.

## The `Connector` interface

```go
type Connector interface {
    Name() string
    Capabilities() pluginhost.Grant
    Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error
}
```

- **`Name`** identifies the connector.
- **`Capabilities`** declares the *least* set of privileges the connector needs,
  using the same grant model as WASM plugins (`pluginhost.Grant`): for example
  `CapFSWrite` constrained to a path, `CapNetDial` to reach a network target, or
  `CapExec` to run a reload command. The connector cannot exceed what it
  declares.
- **`Deploy`** installs `dep` (the certificate and key, as PEM) using only the
  `Sandbox` it is handed — never ambient I/O.

## The `Sandbox`

`Deploy` performs all of its side effects through the `Sandbox`, and every
operation is checked against the connector's declared `Capabilities`. Anything
outside the grant returns `ErrDenied`.

- **`WriteFile`** — write a file at a granted path (for file-based servers like
  NGINX/Apache/HAProxy).
- **`Send`** / request primitives — call a network management API (for appliances
  and cloud targets like F5, ACM, Key Vault).
- **`Exec`** — run a granted command, typically a reload or restart.

## Idempotency

`Deploy` must be **idempotent on `dep.Fingerprint`**: replaying a deploy leaves
the target in the same state. Delivery to connectors is at-least-once (the
orchestrator dispatches through an outbox), and idempotency is what makes the
effect exactly-once. Practically: check whether the target already holds the
credential with that fingerprint before writing, and make the reload safe to
repeat.

## A minimal connector

The `internal/connector/example` package is a complete file-plus-reload connector
(the NGINX/Apache shape): it declares `CapFSWrite` for its config path and
`CapExec` for its reload, writes the PEM with `WriteFile`, and runs the reload
with `Exec`. Start by copying it.

## Conformance

The SDK ships a **conformance suite** (`connector.Conformance`) that exercises a
connector against the host contract — capability enforcement, idempotent replay,
and deployment shape. Wire your connector into it and keep it green; that is what
lets forks and downstream users trust a third-party connector.

```go
func TestMyConnectorConformance(t *testing.T) {
    connector.RunConformance(t, NewMyConnector())
}
```

See `internal/connector/README.md` for the full contract and the list of
in-tree connectors to model yours on.
