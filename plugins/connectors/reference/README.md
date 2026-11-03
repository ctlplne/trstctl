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

## Shipping it as a connector-library module (A242)

A relay runs a module only beside a signed manifest and after its operator
approves it. The manifest names the exact build (`module_sha256`), the host ABI
range it supports, the permissions it asks for (which must fit inside the
relay's `--connector-plugin-capability` grant), its actions, how a retried
deploy converges, what revoke does, the setup inputs a target form asks for,
and its resource limits. For the HTTP reference connector:

```json
{
  "name": "reference-http-connector",
  "version": "1.0.0",
  "module_sha256": "<lowercase hex SHA-256 of reference-http-connector.wasm>",
  "host_api": {"min": 1, "max": 1},
  "permissions": {
    "capabilities": ["net.http"],
    "resources": {"net.http": ["appliance.example:443"]},
    "credentials": ["basic"]
  },
  "actions": ["deploy", "test"],
  "idempotency": "replace-by-name",
  "revocation": "delete",
  "inputs": [{"name": "partition", "type": "string", "required": true, "description": "the appliance partition that holds the certificate"}],
  "limits": {"memory_pages": 16, "timeout_ms": 10000}
}
```

`idempotency` is `replace-by-name` (a retry overwrites the same object),
`create-new` or `read-before-write`; the last two need a `readback` action,
which the relay asks before retrying so a deploy that already landed is not
repeated. A `readback` export returns 0 when the target serves this deploy's
certificate, 1 when it binds another, 2 when nothing is installed and 3 when
the certificate is installed but not bound.

Sign the manifest with the key that signed the module and place
`<name>.manifest.json` and `<name>.manifest.json.sig` beside the `.wasm` and
`.wasm.sig`. Then, on the relay:

- `trstctl-agent --check-connector-modules` (with the relay's plugin flags)
  runs the conformance kit: signatures, manifest, host ABI, grant fit, limits,
  every declared action exported, and a read-only test against a stand-in
  target. It approves nothing.
- `trstctl-agent --approve-connector-module reference-http-connector` prints
  the version, digest, publisher, permissions and what they add over the
  current approval, and records the approval beside the agent's key
  (`--connector-plugin-approvals`). Restart the agent to load it.

A later version that asks for no more loads under the same approval; one that
asks for more, comes from another publisher or is older waits for a new one,
and the relay reports it as awaiting approval instead of running it.
