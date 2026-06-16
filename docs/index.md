# trstctl

**trstctl** is a self-hosted, source-available control plane for every credential
that is *not* a human: X.509 certificates, SSH host and user certificates,
secrets, API keys, tokens, and SPIFFE workload identities. It discovers, issues,
deploys, rotates, revokes, and retires those credentials across hybrid
infrastructure.

trstctl is **source-available, but not open-source**: the full source is published
for you to read and build, but no open-source (OSI-approved) license has been
granted. Nothing in the platform is feature-gated today — the same code runs
whether you self-host or take a commercial license. trstctl is pre-1.0 and under active hardening: see
**[Current limitations](limitations.md)** for an honest account of what the running
binary serves today versus what is built as library code but not yet served.

## Where to start

- **[Getting started](getting-started.md)** — bring up trstctl and issue your
  first certificate in under 15 minutes.
- **[All features](features.md)** — the full catalog of all 78 capabilities, each
  with its own deep-dive page written for both newcomers and experts; start here to
  find anything, and keep the **[glossary](glossary.md)** open if a term is new.
- **[Install](install.md)** — install the control plane and agent on Linux,
  macOS, Windows, Docker, and Kubernetes.
- **[Configuration](configuration.md)** — the bundled vs. external datastore
  switches, server settings, and lifecycle thresholds.
- **[CLI](cli.md)** — drive trstctl from scripts and CI with `trstctl-cli`.
- **[Troubleshooting](troubleshooting.md)** — fixes for the issues people hit
  first.

## Extend it

- **[Authoring a connector](guides/connector-authoring.md)** — deploy renewed
  credentials to a new target.
- **[Authoring a plugin](guides/plugin-authoring.md)** — add a CA or connector as
  a sandboxed WASM plugin.

## How it is built

trstctl is event-sourced and multi-tenant from the first commit, and all
cryptography routes through a single boundary with the private-key operations
isolated in their own process. The [signing service
design](design/signing-service.md) explains the most security-critical of these
boundaries. Usage [telemetry](telemetry.md) is opt-in and off by default.

## License and data

trstctl is **source-available but not open-source**. **The license is undecided** —
no license file is published yet; the specific instrument is still being chosen and
will be added before any public release, and until then **all rights reserved**.
Nothing is feature-gated today; revenue is intended to come from commercial/enterprise
and MSP licensing, support, and a managed offering rather than from withholding
capabilities. It runs entirely on infrastructure you control: PostgreSQL for state and
NATS JetStream for the event log, bundled for single-node evaluation or external for
production.
