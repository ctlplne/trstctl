# Plugins (`plugins/ca`, `plugins/connectors`)

These directories are the drop-in location for third-party / community WASM
plugins — CA integrations (`ca/`) and deployment connectors (`connectors/`) that
are *not* part of the core build. A plugin here is a WASM module loaded by the
plugin host (`internal/pluginhost`, wazero) under an explicit capability grant
and admitted only after passing the conformance suite.

They include source-level reference plugins in this repository:

- `ca/reference/` shows the CA plugin entrypoints (`run`, `issue`) used by the served
  `/api/v1/external-cas/{id}/issue` path.
- `connectors/reference/` shows the connector entrypoint (`run`) used by served
  `connector.deploy` delivery.

Built `.wasm` artifacts are generated and signed outside this tree, then placed in
the operator-configured plugin directories. That separation is intentional: source
is reviewable here, release artifacts are exact-byte signed by the operator.

Do not confuse those reference plugins with the shipped first-party integrations:

- **First-party CAs and connectors do not live here.** The 14 CA integrations
  (`internal/ca/…`) and 24 deployment connectors (`internal/connector/…`) ship as
  trusted in-process Go code, by design — see the
  [plugin trust model & blast radius](../docs/security/threat-model.md) and
  [limitations](../docs/limitations.md). They are not WASM-sandboxed.
- **This directory is for the isolated path.** A plugin dropped here runs in the
  WASM sandbox: no ambient capabilities, only the host functions its grant permits,
  and a fault is contained to its own runtime (the host holds no DB pool or signer
  handle — proven by `internal/pluginhost`'s containment test). That isolation is
  what makes it safe to load code the core team did not write.

## Authoring a plugin

See [`docs/guides/plugin-authoring.md`](../docs/guides/plugin-authoring.md). In
short: build a WASM module that exports the host's run entrypoint, and validate
it against the conformance suite before distribution.

The capability grant is the operator's, not the plugin author's.
The served loader discovers plugins by filename — a `<name>.wasm` with a
detached `<name>.wasm.sig` beside it — and runs every admitted module under the
grant built from `plugins.capabilities` and `plugins.path_prefixes` in the
deployment config. This repository ships no plugin manifest format, so a module
cannot request a narrower grant than the deployment hands it. Keep
`plugins.capabilities` minimal: one grant currently covers the CA, connector and
DNS plugin directories alike.

Built `.wasm` artifacts are **not** committed to this repository; they are produced
by each plugin's own build and distributed separately with a detached `.wasm.sig`.
