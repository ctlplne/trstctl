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

New here? **[Getting started](getting-started.md)** brings up trstctl and gets you your
first certificate in minutes. Then **pick the journey that matches your goal** — each is
an end-to-end walkthrough that chains the features you need:

- **[Issue your first certificate](journeys/first-certificate.md)** — zero to a trusted cert.
- **[Automate TLS across your fleet](journeys/automate-fleet-tls.md)** — ACME, DNS-01, renewal, deploy.
- **[Give Kubernetes workloads an identity](journeys/kubernetes-workload-identity.md)** — SPIFFE, no static secrets.
- **[Enroll devices & IoT fleets](journeys/enroll-devices.md)** — EST, SCEP, CMP.
- **[Migrate from your existing CA](journeys/migrate-from-existing-ca.md)** — discover, stand up, cut over.
- **[Onboard a team as a tenant](journeys/onboard-a-team.md)** — SSO, RBAC, policy, audit.
- **[Manage application secrets](journeys/manage-secrets.md)** — rotation, dynamic secrets, sharing.
- **[Issue & trust SSH at scale](journeys/ssh-at-scale.md)** — SSH CA, deploy/trust, attested certs.
- **[Respond to a compromise](journeys/respond-to-compromise.md)** — revoke, re-issue, break-glass.
- **[Run in production](journeys/run-in-production.md)** — TLS, monitoring, backup/DR, compliance.
- **[Build on the API, CLI & SDKs](journeys/build-on-the-api.md)** — OpenAPI, Go/TS SDKs, the graph.
- **[Stay crypto-agile & migrate to PQC](journeys/crypto-agility-pqc.md)** — inventory, plan, migrate.

Reference docs:

- **[All features](features.md)** — the full catalog of all 78 capabilities, each
  with its own deep-dive page written for both newcomers and experts; start here to
  find anything, and keep the **[glossary](glossary.md)** open if a term is new.
- **[Install](install.md)** — install the control plane and agent on Linux,
  macOS, Windows, Docker, and Kubernetes.
- **[Air-gapped install](airgap.md)** — build an offline bundle, enable the
  no-phone-home guard, and verify certificate issuance plus secret management with
  zero public egress.
- **[Configuration](configuration.md)** — the bundled vs. external datastore
  switches, server settings, and lifecycle thresholds.
- **[Performance SLOs](performance.md)** and
  **[capacity planning](performance-capacity.md)** — the hot-path latency,
  throughput, queue, projection-lag, and right-sizing contract.
- **[CLI](cli.md)** — drive trstctl from scripts and CI with `trstctl-cli`.
- **[Terraform provider](terraform-provider.md)** — manage profiles, short-lived
  PKI credentials, and application secrets from infrastructure-as-code.
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
boundaries. Usage [telemetry](telemetry.md) is opt-in and off by default, and
[air-gapped installs](airgap.md) add a no-phone-home egress guard for disconnected
environments.

## License and data

trstctl is **source-available but not open-source**. **The license is undecided** —
no license file is published yet; the specific instrument is still being chosen and
will be added before any public release, and until then **all rights reserved**.
Nothing is feature-gated today; revenue is intended to come from commercial/enterprise
and MSP licensing, support, and a managed offering rather than from withholding
capabilities. It runs entirely on infrastructure you control: PostgreSQL for state and
NATS JetStream for the event log, bundled for single-node evaluation or external for
production.
