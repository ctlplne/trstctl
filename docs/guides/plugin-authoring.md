# Authoring a plugin

trstctl loads CA integrations and deployment connectors as **WASM plugins** in an
in-process sandbox built on wazero/extism. A plugin runs in its own wazero runtime
with **no ambient syscalls**: the only
privileged operations it can perform are host functions gated by a
**capability** grant it cannot exceed at runtime. Every invocation is submitted
to a shared bounded pool, so a slow or flooded plugin can never starve the
platform.

This model is what lets you — or a third party — ship a CA or connector that the
operator can trust without auditing every line: the host enforces the boundary.

## Capabilities and grants

A plugin is loaded with a `Grant` that names exactly the capabilities it may use,
optionally constrained to a resource (for example, filesystem writes only under a
specific path prefix):

```go
grant := pluginhost.NewGrant(pluginhost.CapFSWrite, pluginhost.CapNetDial).
    WithPathPrefix(pluginhost.CapFSWrite, "/etc/ssl/trstctl")
```

At runtime the host checks each host-function call against the grant
(`grant.Allows(cap, resource)`); anything outside it is denied. Declare the
**least** set of capabilities your plugin needs — the grant is both the security
boundary and the contract you advertise to operators.

## Loading and invoking

The host loads your compiled `.wasm` under its grant and invokes exported
functions:

```go
host := pluginhost.New()
defer host.Close(ctx)

plugin, err := host.Load(ctx, wasmBytes, grant)
if err != nil {
    return err
}
_, err = host.Invoke(ctx, plugin, "deploy")
```

Each `Load` gets its own wazero runtime, and each `Invoke` runs on the host's
bounded worker pool, so concurrency and blast radius stay contained.

## Conformance

Before a plugin is admitted, run it through the host's **conformance suite**,
which validates that it meets the host contract (it exports the required
functions, respects its grant, and behaves under the sandbox):

```go
report := host.Conformance(ctx, wasmBytes)
if !report.OK() {
    log.Fatalf("plugin failed conformance: %+v", report)
}
```

Keep conformance green and publish the result alongside your plugin so downstream
users can self-validate.

## Signing and trusted keys

The served control plane refuses unsigned plugins. A plugin directory entry is
admitted only when the `.wasm` file has a sibling detached Ed25519 signature and
the operator configured the matching public key in `plugins.trusted_key_files`
or `TRSTCTL_PLUGINS_TRUSTED_KEY_FILES`.

Generate a release key, publish the public half, and keep the private key in your
release system:

```bash
openssl genpkey -algorithm Ed25519 -out plugin-signing.key
openssl pkey -in plugin-signing.key -pubout -out plugin-signing.pub.pem
```

Sign the exact bytes you will ship:

```bash
openssl pkeyutl -sign -rawin \
  -inkey plugin-signing.key \
  -in dist/example-connector.wasm \
  -out dist/example-connector.wasm.sig
sha256sum dist/example-connector.wasm
```

Operators place CA modules in `plugins.ca_dir` and connector modules in
`plugins.connector_dir` (the older `plugins.dir` key is still accepted as a
connector-plugin directory). Point `plugins.trusted_key_files` at
`plugin-signing.pub.pem`, and set `plugins.pinned_digests` or
`TRSTCTL_PLUGINS_PINNED_DIGESTS` to the lower-case SHA-256 digest for an
exact-artifact allowlist. An unsigned module, a signature from the wrong key, a
byte-tampered module, or a signed module outside the pinned digest list fails
closed before the WASM runtime is created.

Use these environment variables when running the binary without a config file:

```bash
TRSTCTL_PLUGINS_ENABLED=true
TRSTCTL_PLUGINS_CA_DIR=/etc/trstctl/plugins/ca
TRSTCTL_PLUGINS_CONNECTOR_DIR=/etc/trstctl/plugins/connectors
TRSTCTL_PLUGINS_TRUSTED_KEY_FILES=/etc/trstctl/plugin-signing.pub.pem
```

## Plugins vs. in-tree connectors

If you are deploying to a *target* (a server or cloud API), you usually want a
**connector** rather than a raw WASM plugin — the connector SDK gives you the
same capability/grant model with a much smaller surface. See
[Authoring a connector](connector-authoring.md). Reach for a WASM plugin when you
need to ship an integration as a sandboxed, independently distributed artifact.
