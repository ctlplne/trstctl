# Reference connector WASM plugin

This directory ships the source contract for the reference deployment connector
plugin used by the served plugin host. Build `reference-connector.wat` to
`reference-connector.wasm`, sign the artifact with the operator's Ed25519
plugin-signing key, and place the `.wasm` plus `.wasm.sig` in the configured
`plugins.connector_dir` or legacy `plugins.dir`.

The module exports:

- `run()` for host conformance checks and connector delivery.

The module requests only `fs.write` in this reference fixture. Real connector
plugins should declare only the target-specific capabilities they need.
