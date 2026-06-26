# Extensibility & plugins — add CAs and connectors without trusting their code

## What it is

trstctl can't ship a built-in integration for *every* [CA](../glossary.md) and every
deployment target in the world, so it lets you add them as **plugins**. The
[plugin](../glossary.md) SDK runs third-party plugin code as **WebAssembly (WASM)** inside
a sandbox that grants it only the narrow capabilities it explicitly needs — so a plugin,
even a malicious one, can never reach your database, your keys, or the network beyond what
it was allowed.

The mental model: a plugin is a contractor you let into the building. Instead of handing
them a master key, you give them a single keycard that opens exactly one supply closet and
nothing else, and a guard checks the card at every door. If the contractor turns out to be
hostile, the worst they can do is rummage in that one closet.

## Why it exists

Extensibility usually means running someone else's code with your privileges — which is a
security disaster waiting to happen, especially for a system that holds the keys to your
infrastructure. The whole point of the plugin model is to make extension **safe by
construction**: the host process holds no privileged handle a plugin could grab, the
plugin gets a least-privilege capability grant, and a conformance gate proves a plugin
behaves before you admit it. That's what lets trstctl have an open ecosystem of CA and
connector plugins without widening its attack surface.

## How it works

The plugin host runs each plugin in its **own [WASM](../glossary.md) runtime** (using
wazero), so one plugin's fault or state can't infect another's. At load time the host
builds the plugin's environment with **only the host functions its grant permits** — any
import the plugin declares that wasn't granted causes instantiation to fail, so the
plugin's reach is closed by construction. Every gated call (write a file, dial a host)
checks the [capability grant](../glossary.md) first, including path/host prefix matching,
and denials are counted.

Three properties make this trustworthy:

- **The host holds no privileged handle.** A source-level test asserts the plugin host
  reaches neither the datastore nor the signer — so there is structurally no database pool
  or signing key in its address space for a guest to reach. This is the same containment
  that keeps private-key operations in a separate, isolated signing service, never in
  reach of plugin code.
- **Bounded execution.** Plugin invocations run in a shared bounded lane; a slow or
  runaway plugin is rejected fast rather than starving other subsystems.
- **A conformance gate.** `Conformance` runs a candidate plugin under an *empty* grant and
  asserts it instantiates, exports its entry point, runs without trapping, and performs
  zero privileged operations — the admission check a plugin author runs before shipping.
  A misbehaving-plugin **containment test** proves a hostile plugin is actually contained.

This same capability model is what governs the [deployment connectors](deployment-connectors.md)
and [DNS providers](acme-and-dns.md) — they declare a grant and run sandboxed.

Plugins live under `plugins/ca/` and `plugins/connectors/`.

## Use it

Enable the served plugin surface by pointing trstctl at signed plugin directories:

```toml
[plugins]
enabled = true
ca_dir = "/etc/trstctl/plugins/ca"
connector_dir = "/etc/trstctl/plugins/connectors"
trusted_key_files = ["/etc/trstctl/plugin-signing.pub.pem"]
capabilities = ["fs.write"]
```

CA plugins loaded from `ca_dir` appear in `GET /api/v1/external-cas` with type
`wasm-ca`, and issuance goes through `POST /api/v1/external-cas/{id}/issue`.
Connector plugins loaded from `connector_dir` handle matching `connector.deploy`
work from the served outbox. The legacy `plugins.dir` key remains a connector-plugin
directory alias for older deployments.

A plugin is granted exactly what it needs and nothing more:

```go
h := pluginhost.New()

// grant: may write only under /data, nothing else
grant := pluginhost.NewGrant(pluginhost.CapFSWrite).
    WithPathPrefix(pluginhost.CapFSWrite, "/data")

p, _ := h.Load(ctx, wasmBytes, grant)
out, _ := h.Invoke(ctx, p, "run")

// admission gate: must pass under an EMPTY grant before you trust it
report := h.Conformance(ctx, wasmBytes)   // report.OK() == true to admit
```

To build a CA or connector plugin, follow the
[plugin authoring guide](../guides/plugin-authoring.md) (and the
[connector guide](../guides/connector-authoring.md) for deployment targets).

## Pitfalls & limits

- **Status:** the plugin host is wired into the served binary for signed CA plugins and
  signed connector plugins. The broader plugin marketplace experience is still maturing
  — see [Current limitations](../limitations.md).
- **Grants are deny-by-default.** If a plugin "does nothing," it probably lacked the
  capability for the operation it attempted — that's the sandbox working.
- **WASM constrains what plugins can do** (no arbitrary syscalls); plugins integrate
  through the host functions their grant exposes, not by reaching out directly.
- **Always run `Conformance` before admitting a plugin** — it's the gate that keeps a
  broken or hostile plugin out.

## Reference

- **Host:** `Host.Load(wasm, grant)`, `Host.Invoke(plugin, fn)`,
  `Host.Conformance(wasm)`.
- **Served paths:** `GET /api/v1/external-cas`,
  `POST /api/v1/external-cas/{id}/issue`, and `connector.deploy` delivery.
- **Capabilities:** `CapFSRead`, `CapFSWrite`, `CapNetDial` (and `process.exec` for
  connectors), each path/host prefix-constrainable via `Grant.WithPathPrefix`.
- **Isolation:** one wazero runtime per plugin; bounded invocation pool; host imports no
  store/signer (asserted by test).
- **Plugin trees:** `plugins/ca/`, `plugins/connectors/`.
- **Guides:** [Plugin authoring](../guides/plugin-authoring.md),
  [Connector authoring](../guides/connector-authoring.md).

## See also

[Deployment connectors](deployment-connectors.md) (the same sandbox model) ·
[ACME & DNS](acme-and-dns.md) (DNS-provider plugins) ·
[Plugin authoring guide](../guides/plugin-authoring.md) ·
[Product threat model](../security/threat-model.md) ·
glossary: [plugin / WASM sandbox](../glossary.md), [bulkhead](../glossary.md)

**Covers:** F20
