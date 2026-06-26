# Reference CA WASM plugin

This directory ships the source contract for the reference CA plugin used by the
served plugin host. Build `reference-ca.wat` to `reference-ca.wasm`, sign the
artifact with the operator's Ed25519 plugin-signing key, and place the `.wasm`
plus `.wasm.sig` in the configured `plugins.ca_dir`.

The module exports:

- `run()` for host conformance checks.
- `issue()` for the served CA path behind `/api/v1/external-cas/{id}/issue`.

The module requests only `fs.write` in this reference fixture. Real CA plugins
should request the smallest capability set required for their upstream CA API.
Crypto agility remains compile-time Go interfaces and dependency injection behind
`internal/crypto`; plugins are not runtime crypto-provider engines.
