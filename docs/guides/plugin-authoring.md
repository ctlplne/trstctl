# Authoring a plugin

trstctl loads CA integrations and deployment connectors as **WASM plugins** in an
in-process sandbox (package `internal/pluginhost`, built on wazero/extism). A
plugin runs in its own wazero runtime with **no ambient syscalls**: the only
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
bounded worker pool (AN-7), so concurrency and blast radius stay contained.

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

## Plugins vs. in-tree connectors

If you are deploying to a *target* (a server or cloud API), you usually want a
**connector** rather than a raw WASM plugin — the connector SDK gives you the
same capability/grant model with a much smaller surface. See
[Authoring a connector](connector-authoring.md). Reach for a WASM plugin when you
need to ship an integration as a sandboxed, independently distributed artifact.
