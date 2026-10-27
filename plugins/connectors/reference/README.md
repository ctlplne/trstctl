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

`reference-http-connector.wat` deploys over an appliance's HTTP API from a relay.
It asks the relay to make its requests with `cap_http` (grant `net.http`,
constrained to the appliance's `host:port`): the relay adds the target's
credential, splices the certificate and private key into the JSON body by
reference, and removes every redeemed value from the reply, so the module never
holds the password or the key. It also exports `test()`, which the relay runs
under a read-only grant for a connector test. Grant it on the relay with
`--connector-plugin-capability net.http` and
`--connector-plugin-capability-prefix net.http=<appliance>:443`.
